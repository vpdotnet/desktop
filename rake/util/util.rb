module Util
    def self.joinPathArrays(prefixes, suffixes)
        prefixes.flat_map { |prefix| suffixes.map { |suffix| File.join(prefix, suffix) } }
    end

    def self.joinPaths(componentArrays)
        componentArrays.reduce { |accumulator, componentArray| Util.joinPathArrays(accumulator, componentArray) }
    end

    # Find a value in an array matching a predicate - unlike find_index(),
    # returns the value itself
    def self.find(array, &block)
        idx = array.find_index(&block)
        (idx != nil) ? array[idx] : nil
    end

    # Select a symbol based on a value found from the environment.  If the
    # variable is not present or empty, the default value is returned (with no
    # warning).
    #
    # Unlike String.to_sym(), this fails the build if an unexpected value is
    # given
    def self.selectSymbol(varName, default, symbols)
        value = ENV[varName].to_s
        if(value == '')
            default
        else
            symbolIdx = symbols.find_index {|s| value == s.to_s}
            if(symbolIdx == nil)
                raise "Unknown value for #{varName}: #{value}"
            else
                symbols[symbolIdx]
            end
        end
    end

    def self.selectBooleanSymbol(varName, default)
        truthy_symbols = [:on, :yes, :true, 1]
        falsey_symbols = [:off, :no, :false, 0]
        value = selectSymbol(varName, default, truthy_symbols + falsey_symbols + [:undefined])
        if truthy_symbols.include? value
            return true
        elsif falsey_symbols.include? value
            return false
        else
            return value
        end
    end

    def self.hostPlatform
        # "darwin" includes "win", so check it first
        if(RUBY_PLATFORM.include?('darwin'))
            :macos
        elsif(RUBY_PLATFORM.include?('win') || RUBY_PLATFORM.include?('mingw'))
            :windows
        elsif(RUBY_PLATFORM.include?('linux'))
            :linux
        else
            puts "Platform not known: #{RUBY_PLATFORM}"
            nil
        end
    end

    def self.hostArchitecture
        if(hostPlatform == :windows)
            archProbe = `powershell -Command "(Get-CimInstance Win32_OperatingSystem).OSArchitecture"`.strip
            if(archProbe.match?(/^64-bit$/i))
                :x86_64
            elsif(archProbe.match(/^32-bit$/i))
                :x86
            else
                puts "Architecture not known: #{archProbe.dump}"
                nil
            end
        elsif(hostPlatform == :linux || hostPlatform == :macos)
            uname_m = `uname -m`.strip
            if(uname_m == 'x86_64')
                :x86_64
            elsif(uname_m == 'armv7l')
                :armhf
            elsif(uname_m == 'aarch64' || uname_m == 'arm64')
                :arm64
            else
                puts "Architecture not known: #{uname_m}"
            end
        end
    end

    # Ruby 2.3.1 on Ubuntu 16.04 lacks String.delete_prefix/delete_suffix
    def self.deletePrefix(val, prefix)
        return val unless val.start_with?(prefix)
        val.slice(prefix.length..-1)
    end
    def self.deleteSuffix(val, suffix)
        return val unless val.end_with?(suffix)
        val.slice(0..(-suffix.length-1))
    end

    # On Windows, run a command using the cmd.exe shell (returns the complete
    # command line, can be invoked with sh, backticks, etc.)
    def self.cmd(command)
        # cmd.exe uses peculiar quoting semantics; any quotes in 'command' do not
        # need to be escaped.  It seems to look for the very last quote to
        # terminate the /C argument, and all intervening quotes are preserved
        # as-is when executing the command.
        "#{ENV['ComSpec']} /C \"#{command}\""
    end

    # Retrieve the command verbosity specified by the caller. Defaults to false
    def self.verbose?
        verboseSymbol = selectBooleanSymbol('VERBOSE', :undefined)
        if verboseSymbol == :undefined 
            verboseSymbol = selectBooleanSymbol('RAKE_VERBOSE_SH', :undefined)
            if verboseSymbol != :undefined 
                return verboseSymbol
            end
            return false
        end
        return verboseSymbol
    end

    def self.shellRun(*cmd)
        Rake.sh *cmd, verbose: self.verbose? do |ok, res|
            if !ok
                # Escape cmd args for easier debugging
                escaped_cmd = cmd.map { |arg| arg.include?(' ') ? "\"#{arg}\"" : arg }.join(' ')
                raise "Command failed: #{escaped_cmd}"
            end
        end
    end
end
