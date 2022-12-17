#!/usr/bin/env ruby
=begin
In .tmux.conf:
  run 'tmux-ssh-agent proxy'

In your shell's login profile:
  if [ -z "$TMUX" ] && [ -n "$SSH_AUTH_SOCK" ]; then
    tmux-ssh-agent register-agent
  fi
=end

USAGE = <<EOF
Usage:
  # Start proxy SSH agent under tmux server
  #{$0} proxy

  # Register SSH agent for the current TTY
  #{$0} register-agent [SSH_AUTH_SOCK]

  # Register default SSH agent
  #{$0} register-default-agent [--override] [SSH_AUTH_SOCK]

  # Lists all the registered SSH agents
  #{$0} list-agents
EOF

require 'json'
require 'pathname'
require 'securerandom'
require 'socket'

module TmuxSSHAgentProxy
  def self.runtime_dir
    unless runtime_dir = ENV['RUNTIME_DIRECTORY']
      if runtime_dir_root = ENV['XDG_RUNTIME_DIR']
        runtime_dir = Pathname(runtime_dir_root).join('tmux-ssh-agent-proxy')
      else
        require 'tmpdir'
        runtime_dir = Pathname(Dir.tmpdir).join("tmux-ssh-agent-proxy-#{Process.uid}")
      end

      begin
        runtime_dir.mkdir(0700)
      rescue Errno::EEXIST
      end
    end

    Pathname(runtime_dir)
  end

  class Tmux
    TMUX_CMD = 'tmux'

    def self.ping
      IO.popen([TMUX_CMD, 'display-message', '-p', '1'], &:read).chomp == '1'
    end

    def self.set_environment(name, value)
      system(TMUX_CMD, 'set-environment', '-g', name, value.to_s)
    end

    def self.current_client
      IO.popen([TMUX_CMD, 'list-client', '-F', '#{client_activity}:#{client_tty}']) do |f|
        f.each_line.map {|l| l.chomp.split(?:, 2) }.max_by {|p| p[0].to_i }[1]
      end
    end
  end

  module SSHAgentProtocol
    SSH_AGENT_FAILURE = 5
    SSH_AGENT_SUCCESS = 6
  end

  module SSHAgentSocket
    FAILURE = [SSHAgentProtocol::SSH_AGENT_FAILURE].pack('C')

    def recv_packet
      unless len = self.recv(4).unpack1('N')
        return  # EOF
      end
      payload = self.recv(len)
    end

    def send_packet(payload)
      self.send([payload.bytesize, payload].pack('Na*'), 0)
    end

    def request(payload)
      send_packet(payload)
      recv_packet
    end

    def handle_request(&handler)
      if payload = recv_packet
        response = handler.call(payload)
        send_packet(response)
        true
      end
    end
  end

  class StateFile
    def initialize(path)
      @path = path
    end

    def lock(&)
      File.open(@path, File::RDWR | File::CREAT) do |f|
        f.flock(File::LOCK_EX)

        state = cleanup(
          begin
            s = JSON.parse(f.read)
            s.is_a?(Hash) ? s : {}
          rescue JSON::ParserError
            {}
          end
        )

        yield state
      ensure
        f.truncate(0)
        f.rewind
        JSON.dump(state, f)
      end
    end

    private

    def cleanup(state)
      {
        'agents' => state.fetch('agents', {}).filter {|_, agent| File.exist?(agent) }.to_h,
        'default_agent'=> begin
                            if default_agent = state['default_agent'] and File.exist?(default_agent)
                              default_agent
                            end
                          end,
      }
    end
  end

  class ProxyAgent
    def initialize
      @state_file = StateFile.new(TmuxSSHAgentProxy.runtime_dir / 'state')
      @workers = ThreadGroup.new
    end

    def run(ready: nil)
      path = TmuxSSHAgentProxy.runtime_dir / SecureRandom.hex(16)
      listen(path) do |socket|
        Tmux.set_environment('SSH_AUTH_SOCK', path)

        ready&.call

        while Tmux.ping
          begin
            @workers.add(Thread.new(socket.accept_nonblock, &method(:serve_client)))
          rescue IO::WaitReadable
            IO.select([socket], [], [], 3)
          end
        end

        @workers.list.each(&:join)
      end
    end

    private

    def serve_client(downstream_socket)
      downstream_socket.extend(SSHAgentSocket)

      agent = @state_file.lock do |state|
        if tty = Tmux.current_client
          state.dig('agents', tty)
        else
          state['default_agent']
        end
      end or return

      UNIXSocket.open(agent) do |upstream_socket|
        upstream_socket.extend(SSHAgentSocket)

        loop do
          downstream_socket.handle_request do |payload|
            upstream_socket.request(payload) || SSHAgentSocket::FAILURE
          end or break
        end
      end
    ensure
      downstream_socket.close
    end

    def listen(path, &block)
      UNIXServer.open(path, &block)
    ensure
      path.unlink rescue nil
    end
  end

  class Control
    def initialize
      @state_file = StateFile.new(TmuxSSHAgentProxy.runtime_dir / 'state')
    end

    def register_agent(tty, agent)
      @state_file.lock do |state|
        state['agents'][tty] = agent
      end
    end

    def register_default_agent(tty, agent, override: false)
      @state_file.lock do |state|
        if override
          state['default_agent'] = agent
        else
          state['default_agent'] ||= agent
        end
      end
    end

    def state
      @state_file.lock {|state| state }
    end
  end

  class CLI
    def run(args)
      case args.shift
      when 'proxy'
        fail 'Not running under tmux server' unless ENV.key?('TMUX')
        if args.delete('--no-daemon')
          ProxyAgent.new.run
        else
          r, w = IO.pipe

          fork do
            r.close

            Process.daemon
            ProxyAgent.new.run(ready: ->() { w.write('ok'); w.close })
          end

          w.close
          ok = r.read(2) == 'ok'
          r.close
          exit(ok ? 0 : 1)
        end
      when 'register-agent'
        Control.new.register_agent(
          tty,
          args[0] || ssh_auth_sock || fail('No SSH_AUTH_SOCK specified')
        )
      when 'register-default-agent'
        override = args.delete('--override')
        Control.new.register_default_agent(
          tty,
          args[0] || ssh_auth_sock || fail('No SSH_AUTH_SOCK specified'),
          override:,
        )
      when 'list', 'list-agents'
        state = Control.new.state
        if default_agent = state['default_agent']
          puts "  default: #{default_agent}"
        end
        state['agents'].each do |client, agent|
          puts "#{client == tty ? '* ' : '  '}#{client}: #{agent}"
        end
      else
        $stderr.puts USAGE
        exit 1
      end
    rescue => e
      $stderr.puts e.message
      exit 1
    end

    private

    def tty
      @tty ||= ENV['SSH_TTY'] || `tty`.chomp
    end

    def ssh_auth_sock
      @ssh_auth_sock ||= ENV['SSH_AUTH_SOCK']
    end
  end
end

Thread.report_on_exception = true
TmuxSSHAgentProxy::CLI.new.run(ARGV)
