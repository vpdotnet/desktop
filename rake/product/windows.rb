require_relative '../executable.rb'
require_relative '../archive.rb'
require_relative '../product/version.rb'
require_relative '../model/build.rb'
require_relative '../util/dsl.rb'

module PiaWindows
    extend BuildDSL

    SignCertFile = ENV['PIA_SIGNTOOL_CERTFILE']
    SignPassword = ENV['PIA_SIGNTOOL_PASSWORD']
    SignThumbprint = ENV['PIA_SIGNTOOL_THUMBPRINT']
    GCloudKeyId = ENV['GOOGLE_CLOUD_KEY_ID']
    SkipSigning = !ENV['PIA_SKIP_SIGNING'].nil?
    CanSign = Build::release? && ((SignCertFile != nil) || (SignThumbprint != nil)) && !SkipSigning
    # Override this value manually if you need to test signing locally with a 
    # dev cert or hardware token
    UseGCloudSigning = (GCloudKeyId != nil)

    # Base setup for uninstaller/installer; these are built from the same source
    # with either INSTALLER or UNINSTALLER defined
    def self.winstaller(name, version)
        target = Executable.new(name, :executable)
            .gui
            .define('_STATIC_CPPLIB')
            .runtime(:static)
            .use(version.export)
            .source('extras/installer/win')
            .source('extras/installer/win/tasks')
            .source('extras/installer/win/translations') # translated string resources
            .sourceFile("brands/#{Build::Brand}/brand_installer.rc")
            .linkArgs([
                "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'",
                # Specify these as delay-loaded since they're not "known DLLs" (i.e.
                # can be subject to executable path lookup rules)
                # By delaying it we allow our anti-hijacking rules to
                # apply (see _tWinMain in win/main.cpp) which tightly control
                # DLL load paths.
                'delayimp.lib',
                '/DELAYLOAD:newdev.dll',
                '/DELAYLOAD:userenv.dll',
                '/DELAYLOAD:msi.dll',
                '/DELAYLOAD:bcrypt.dll'
            ])
        # Include pseudolocalizations only in debug builds
        target.source('extras/installer/win/translations/debug') if Build::debug?
        target
    end

    # Find the MSVC/UCRT runtime files and add them to an installation target
    def self.installRuntime(target)
        arch = (Build::TargetArchitecture == :x86_64) ? 'x64' : Build::TargetArchitecture.to_s

        msvcLibs = [ 'msvcp140', 'msvcp140_1', 'msvcp140_2', 'vcruntime140' ]
        # vcruntime140_1.dll is required on x86_64 (SEH fix in VC runtime), but
        # does not exist at all on x86
        if(Build::TargetArchitecture == :x86_64)
            msvcLibs << 'vcruntime140_1'
        end

        crtDir = File.absolute_path(ENV['VCToolsRedistDir'])
        if(Build::debug?)
            crtDir = File.join(crtDir, 'debug_nonredist')
        end

        crtFound = false
        for vcVer in ["VC143", "VC142"]
            vcCrtDir = File.join(crtDir, arch,
                Build::debug? ? 'Microsoft.'+vcVer+'.DebugCRT' : 'Microsoft.'+vcVer+'.CRT')
            if File.exist?(vcCrtDir)
                crtDir = vcCrtDir
                crtFound = true
                break
            end
            puts "Couldn't find " + vcVer
        end

        if !File.exist?(crtDir) or !crtFound
            raise "error: cannot find CRT. Install MSVC v142+"
        end

        msvcLibs.each do |l|
            libPath = File.join(crtDir, "#{l}#{Build.debug? ? 'd' : ''}.dll")
            target.install(libPath, '/')
        end

        ucrtPattern = ''
        if(Build::debug?)
            # Find the last SDK version
            # Normalize to / for FileList to work
            winSdkPath = File.absolute_path(ENV['WindowsSdkBinPath'])
            lastSdk = FileList[File.join(winSdkPath, '10.*')].max
            ucrtPattern = File.join(lastSdk, arch, 'ucrt/*.dll')
        else
            winSdk = File.absolute_path(ENV['WindowsSdkDir'])
            ucrtPattern = File.join(winSdk, 'Redist/ucrt/DLLs', arch, '*.dll')
        end

        FileList[ucrtPattern].each { |l| target.install(l, '/') }
    end

    # Invoke windeployqt on Windows
    def self.winDeploy(qmlDirs, binaryFilePaths)
        # Sometimes we do need the windeployqt output to see what libraries it
        # found, etc., but the verbose output also spews a line for every
        # qml/qmlc file it copies so it's off by default :-/
        args = [Executable::Qt.tool('windeployqt'), '-verbose', '0']
        args += qmlDirs.flat_map{|d| ['--qmldir', File.absolute_path(d)]}
        args += [
            '--no-compiler-runtime',
            '--no-translations', '--no-opengl-sw'
        ]
        args += binaryFilePaths
        Util.shellRun *args

        if Build::TargetArchitecture == :arm64
            # Arm deployment doesn't really work, so we will manually go through
            # all Qt dlls and change them for their arm64 counterpart.
            targetRoot = Executable::Qt.targetQtRoot

            # Create a hashmap to store all DLL paths available in the targetQt
            dllMap = {}

            # Populate the hashmap with DLL filenames and their full paths
            Dir.glob(File.join(targetRoot, '**/*.dll')).each do |file|
                dllMap[File.basename(file)] = file
            end

            # Find all .dll files in the current directory and its subdirectories
            Dir.glob(File.join(Build::BuildDir, '**/*.dll')).each do |stagedDllPath|
                dllName = File.basename(stagedDllPath)
                if dllMap.key?(dllName)
                    # Replace the original DLL with the one from the target directory
                    FileUtils.cp(dllMap[dllName], stagedDllPath)
                    puts "Replaced: #{stagedDllPath} with #{dllMap[dllName]}"
                else
                    puts "No corresponding file found for: #{stagedDllPath}"
                end
            end
        end
    end

    # Invoke signtool on Windows - signs one time
    # - files - absolute paths to files to sign, with Windows separators
    # - first - whether this is the first signature or an additional signature
    # - hash_alg - hash algorithm to use in signature, 'sha1' or 'sha256'
    # - useTimestamp - whether to use a timestamping authority
    # - description - if non-nil, file description passed to signtool
    def self.signtool(files, first, hash_alg, useTimestamp, description)
        args = [
            'signtool', # Placed in PATH by vcvars
            'sign'
        ]
        args << '/as' unless first # append signature if not the first one
        args << '/fd'
        args << hash_alg
        args << '/v'
        args << '/debug' # Extra information
        if(useTimestamp)
            args << '/tr'
            args << 'http://timestamp.digicert.com'
            args << '/td'
            args << hash_alg
        end
        # Cert args - can be specified with a file + password, a thumbprint,
        # or google cloud token. These values are taken from environment variables
        if UseGCloudSigning
            args << '/f'
            args << SignCertFile
            args << '/csp'
            args << 'Google Cloud KMS Provider'
            args << '/kc'
            args << GCloudKeyId
        elsif(SignThumbprint != nil)
            # Sign using hardware token or certificate from Windows certificate store
            args << '/sha1'
            args << SignThumbprint
            # Additional options for hardware tokens if needed
            if ENV['PIA_SIGNTOOL_CSP'] != nil
                args << '/csp'
                args << ENV['PIA_SIGNTOOL_CSP']
            end
            if ENV['PIA_SIGNTOOL_KEYCONTAINER'] != nil
                args << '/kc'
                args << ENV['PIA_SIGNTOOL_KEYCONTAINER']
            end
        elsif(SignCertFile != nil)
            args << '/f'
            args << SignCertFile
            if(SignPassword != nil)
                args << '/p'
                args << SignPassword
            end
        end
        # File description
        if(description != nil)
            args << '/d'
            args << description
        end


        # Signing tends to be flaky as it depends on network and there's some
        # signtool bug when using CNG. It's uncommon enough that retrying a 
        # few times should solve the problem. If it keeps failing we'll need a 
        # fancier solution.
        attempts = 0
        maxAttempts = 10
        while true
            begin
                attempts += 1
                Util.shellRun *(args + files)
            rescue => error
                if attempts < maxAttempts
                    puts "Signing failed, will retry"
                else
                    puts "Signing failed too many times, will abort"
                    raise error
                end
            else
                break
            end
        end
    end

    # Double-sign files using both SHA-1 and SHA-256.
    # There's a slight error here that we're still using a SHA-256 certificate
    # in the SHA-1 signature - there's no way to specify two separate certs.
    # However, only Windows 7 RTM lacks SHA-256 signature support (and it's
    # available in an update), so this isn't going to be fixed at this point.
    def self.doubleSign(files, useTimestamp, description)
        # Get absolute, Windows-style paths
        files = files.map {|f| File.absolute_path(f).gsub!('/', '\\')}

        signtool(files, false, 'sha256', useTimestamp, description)
    end

    # Define additional installable artifacts and targets for Windows.
    def self.defineTargets(version, stage, kappsModules, commonlib, clientlib)
        # This module is used by the client to indirectly access Windows Runtime
        # APIs.  The client remains compatible with Windows 7 by only loading this
        # module on 8+.  The Windows Runtime APIs themselves are spread among
        # various modules, so this level of indirection avoids introducing a hard
        # dependency on any of those modules from the client itself.
        winrtsupport = Executable.new("#{Build::Brand}-winrtsupport", :dynamic)
            .source('extras/winrtsupport/src')
            .use(commonlib.export)
            .install(stage, '/')

        # Service stub used to replace the Dnscache service for split tunnel
        # DNS; see win_dnscachecontrol.cpp
        winsvcstub = Executable.new("#{Build::Brand}-winsvcstub")
            .source('extras/winsvcstub/src')
            .use(commonlib.export)
            .install(stage, '/')

        # MSVC and UCRT runtime file - enumerate the files and add install targets
        installRuntime(stage)

        # Drivers
        FileList["deps/tap/win/#{Build::TargetArchitecture}/win*/*"].each do |f|
            # Install to win7/* or win10/*
            winVerDir = File.basename(File.dirname(f))
            stage.install(f, "tap/#{winVerDir}/")
        end
        FileList["deps/wfp_callout/win/#{Build::TargetArchitecture}/win*/*"].each do |f|
            winVerDir = File.basename(File.dirname(f))
            stage.install(f, "wfp_callout/#{winVerDir}/")
        end

        # OpenVPN updown script (used for 'static' configuration method)
        stage.install('extras/openvpn/win/openvpn_updown.bat', '/')

        # zip.exe, used by support tool on Windows
        stage.install('deps/zip/zip.exe', '/')

        # Windows uninstaller
        uninstall = winstaller('uninstall', version)
            .define('UNINSTALLER')
            .install(stage, '/')
    end

    # Define the task to build the Windows installer artifact.  This depends on the
    # staged output and becomes a dependency of the :installer task.
    def self.defineInstaller(version, stage, artifacts)
        # This task (and the following tasks to compress / sign / link installer)
        # will always run since the staging task always runs.
        task :windeploy => stage.target do |t|
            # The CLI executable is excluded from the deploy binaries, for some
            # reason including that prevents windeployqt from deploying any QtQuick
            # dependencies.  Fortunately, it doesn't have any specific dependencies
            # of its own.
            deployExes = ["#{Build::Brand}-client.exe", "#{Build::Brand}-service.exe"]
            winDeploy(['client/res/components', 'extras/support-tool/components'],
                      deployExes.map {|f| File.join(stage.dir, f)})
        end

        task :winsign => :windeploy do |t|
            # Nothing to do if we can't sign
            if(CanSign)
                fileDescriptions = {}
                fileDescriptions["#{Build::Brand}-client.exe"] = version.productName
                fileDescriptions["#{Build::Brand}-service.exe"] = "#{version.productName} Service"
                fileDescriptions["uninstall.exe"] = "#{version.productName} Uninstaller"

                namedFiles = []
                unnamedExes = []
                unnamedDlls = []

                FileList[File.join(stage.dir, '*')].each do |f|
                    if(fileDescriptions.include?(File.basename(f)))
                        namedFiles << f
                    elsif(File.extname(f) == '.exe')
                        unnamedExes << f
                    elsif(File.extname(f) == '.dll')
                        unnamedDlls << f
                    end
                end

                namedFiles.each do |f|
                    doubleSign([f], true, fileDescriptions[File.basename(f)])
                end
                doubleSign(unnamedExes, true, nil) unless unnamedExes.empty?
                doubleSign(unnamedDlls, false, nil) unless unnamedDlls.empty?
            end
        end

        # Build the payload with 7-zip.
        payloadBuild = Build.new('payload')
        payload = payloadBuild.artifact('payload.7z')
        file payload => [:winsign, payloadBuild.componentDir] do |t|
            Archive.zipDirectoryContents(stage.dir, payload)
        end

        # Create a resource script to include the payload data in the installer.
        # This depends on the payload so the installer has an indirect
        # dependency.
        payloadRc = payloadBuild.artifact('payload.rc')
        file payloadRc => [payload, payloadBuild.componentDir] do |t|
            File.write(t.name, "1337 RCDATA \"#{File.absolute_path(payload)}\"\n")
        end

        # The installer uses the LZMA SDK from 7-zip
        lzmaSdk = Executable.new("lzma-sdk", :static)
            .define('_STATIC_CPPLIB')
            .runtime(:static)
            .source('deps/lzma/src', :export)

        # Build the installer using the payload
        install = winstaller(version.packageName, version)
            .define('INSTALLER')
            .use(lzmaSdk.export)
            .sourceFile(payloadRc)

        # Sign the installer and put it in a predicatable location for job
        # artifacts to pick up
        installerBuild = Build.new('installer')
        signedInstaller = installerBuild.artifact(File.basename(install.target))
        file signedInstaller => [install.target, installerBuild.componentDir] do |t|
            puts "sign: #{signedInstaller}"
            FileUtils.copy(install.target, signedInstaller)
            if(CanSign)
                doubleSign([signedInstaller], true, "#{version.productName} Installer")
            end
        end

        artifacts.install(signedInstaller, '')

        task :installer => signedInstaller
    end

    # Define targets for tools built just for development use (not part of the
    # build process itself or shipped artifacts).
    #
    # Since these are just development workflow tools, they can be skipped if
    # specific dependencies are not available.
    def self.defineTools(toolsStage)
        Executable.new("#{Build::Brand}-closegui")
            .source('tools/closegui')
            .install(toolsStage, :bin)
        Executable.new("win-httpstunnel")
            .source('tools/win-httpstunnel')
            .install(toolsStage, :bin)
    end

    def self.collectSymbols(version, stage, debugSymbols)
        symbolsDir = debugSymbols.artifact("symbols-#{version.packageName}")
        FileUtils.mkdir(symbolsDir)
        FileList.new(File.join(stage.dir, '**/*.exe'), File.join(stage.dir, '**/*.dll'))
            .each do |f|
                FileUtils.copy_entry(f, File.join(symbolsDir, File.basename(f)))
                modName = File.basename(f, '.*')
                pdbPath = File.join(Build::BuildDir, modName, modName + '.pdb')
                if(File.exist?(pdbPath))
                    FileUtils.copy_entry(pdbPath, File.join(symbolsDir, modName + '.pdb'))
                end
            end
    end
end
