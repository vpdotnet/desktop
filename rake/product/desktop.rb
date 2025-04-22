require_relative '../executable.rb'
require_relative '../archive.rb'
require_relative '../product/version.rb'
require_relative '../model/build.rb'
require_relative '../util/dumpsyms'
require_relative '../util/dsl.rb'
require_relative '../makeqtsymbols'
require_relative 'windows' if Build.windows?
require_relative 'macos' if Build.macos?
require_relative 'linux' if Build.linux?

module PiaDesktop
    extend BuildDSL

    def self.defineTargets(version, versionlib, deps, kappsModules, artifacts, toolsStage)
        # Stage - install target to prepare the installed application bundle.  The
        # installer is then built from this directory.
        stage = Install.new(Build.macos? ? "stage/#{version.productName}.app" : 'stage')

        # Install the kapps modules with Desktop
        kappsModules[:core].install(stage, :lib)
        kappsModules[:net].install(stage, :lib)
        kappsModules[:regions].install(stage, :lib)

        commonlib = Executable.new("#{Build::Brand}-commonlib", :dynamic)
            .define('BUILD_COMMON')
            .source('common/src')
            .source('common/src/builtin')
            .source('common/src/settings')
            .use(versionlib.export, :export)
            .use(kappsModules[:core].export, :export)
            .use(kappsModules[:regions].export, :export)
            .useQt('Network', :export)
            .tap {|v| PiaBreakpad::add(v)}
            .install(stage, :lib)

        clientlib = Executable.new("#{Build::Brand}-clientlib", :dynamic)
            .define('BUILD_CLIENTLIB')
            .define('PIA_CLIENT', :export)
            .define('KAPPS_CORE_FULL_WINAPI', :export) # Don't exclude GUI APIs, see kapps-core/src/win/winapi.h
            .source('clientlib/src')
            .source('clientlib/src/model')
            .use(commonlib.export, :export)
            .install(stage, :lib)

        if(Build.macos?)
            clientlib.framework('AppKit')
        end

        cli = Executable.new("#{Build::Brand}ctl", :executable)
            .source('cli/src')
            .use(clientlib.export)
            .install(stage, :bin)

        clientName = Build.macos? ? version.productName : "#{Build::Brand}-client"
        client = Executable.new(clientName, :executable)
            .gui
            .source('client/src')
            .source('client/src/nativeacc')
            .use(clientlib.export)
            .resource('client/res', ['**/*'],
                ['**/*.qrc', '**/*.svg', '**/*.sh', '**/*.otf',
                '**/RobotoCondensed-*.ttf', '**/Roboto-*Italic.ttf',
                '**/Roboto-Black.ttf', '**/Roboto-Medium.ttf', '**/Roboto-Thin.ttf'])
            .resource("brands/#{Build::Brand}", ['img/**/*'])
            .resource("brands/#{Build::Brand}/gen_res", ['img/**/*'])
            .resource('.', ['CHANGELOG.md', 'BETA_AGREEMENT.md'])
            .useQt('Qml')
            .useQt('Quick')
            .useQt('QuickControls2')
            .useQt('Gui')
            .install(stage, :bin)
        if(Build.windows?)
            client
                .sourceFile("brands/#{Build::Brand}/brand_client.rc")
                .linkArgs(["/MANIFESTINPUT:#{File.absolute_path('client/src/win/res/dpiManifest.xml')}"])
        elsif(Build.macos?)
            client
                .include('extras/installer/mac/helper')
                .framework('AppKit')
                .framework('Security')
                .framework('ServiceManagement')
        elsif(Build.linux?)
            client
                .useQt('Widgets')
        end
        client.define("QT_QML_DEBUG") if Build.debug?

        # Translation resource file for client, and OneSky export
        defineTranslationTargets(stage, artifacts)

        supportTool = Executable.new("#{Build::Brand}-support-tool", :executable)
            .gui
            .source('extras/support-tool')
            .resource('extras/support-tool', ['components/**/*', 'qtquickcontrols2.conf'])
            .use(commonlib.export)
            .use(version.export)
            .useQt('Qml')
            .useQt('Quick')
            .useQt('QuickControls2')
            .useQt('Gui')
            .useQt('Widgets')
            .install(stage, :bin)

        daemonName = Build.windows? ? "#{Build::Brand}-service" : "#{Build::Brand}-daemon"
        daemon = Executable.new(daemonName, :executable)
            .source('daemon/src')
            .source('deps/embeddable-wg-library/src')
            .source('deps/wintun/src')
            .source('daemon/src/model')
            .resource('daemon/res', ['ca/*.crt'])
            .use(commonlib.export)
            .use(kappsModules[:net].export)
            .use(deps[:embeddablewg].export)
            .install(stage, :bin)

        if(Build.windows?)
            daemon
                .useQt('Xml')
                .linkArgs(["/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"])
        elsif(Build.macos?)
            daemon
                .framework('AppKit')
                .framework('CoreWLAN')
                .framework('SystemConfiguration')
        elsif(Build.linux?)
            daemon.include('/usr/include/libnl3')
        end

        # Install LICENSE.txt
        stage.install('LICENSE.txt', :res)

        # Download server lists to ship preloaded copies with the app.  These tasks
        # depend on version.txt so they're refreshed periodically (whenver a new commit
        # is made), but not for every build.
        #
        # SERVER_DATA_DIR can be set to use existing files instead of downloading them;
        # this is primarily intended for reproducing a build.
        #
        # Create a probe for SERVER_DATA_DIR so these are updated if it changes.
        serverDataProbe = Probe.new('serverdata')
        serverDataProbe.file('serverdata.txt', "#{ENV['SERVER_DATA_DIR']}")
        # JSON resource build directory
        jsonFetched = Build.new('json-fetched')
        # These are the assets we need to fetch and the URIs we get them from
        {
            'modern_shadowsocks.json': 'https://vp.net/_rest/Network/VPN:serverlist?resource=/shadow_socks',
            'modern_servers.json': 'https://vp.net/_rest/Network/VPN:serverlist?resource=/vpninfo/servers/v6',
            'modern_region_meta.json': 'https://vp.net/_rest/Network/VPN:serverlist?resource=/vpninfo/regions/v2'
        }.each do |k, v|
            fetchedFile = jsonFetched.artifact(k.to_s)
            serverDataDir = ENV['SERVER_DATA_DIR']
            file fetchedFile => [version.artifact('version.txt'),
                                serverDataProbe.artifact('serverdata.txt'),
                                jsonFetched.componentDir] do |t|
                if(serverDataDir)
                    # Use the copy provided instead of fetching (for reproducing a build)
                    File.copy(File.join(serverDataDir, k), fetchedFile)
                else
                    # Fetch from the web API (write with "binary" mode so LF is not
                    # converted to CRLF on Windows)
                    File.binwrite(t.name, Net::HTTP.get(URI(v)))
                end
            end
            stage.install(fetchedFile, :res)
        end

        # Install version/brand/arch info in case an upgrade needs to know what is
        # currently installed
        stage.install(version.artifact('version.txt'), :res)
        stage.install(version.artifact('brand.txt'), :res)
        stage.install(version.artifact('architecture.txt'), :res)

        # Install dependencies built separately
        depDirs = [
            'deps/built'
        ]
        depPlatformDir = ''
        depPlatformDir = 'win' if Build::windows?
        depPlatformDir = 'mac' if Build::macos?
        depPlatformDir = 'linux' if Build::linux?
        dynamicExt = Build::selectDesktop(".dll", ".dylib", ".so")
        depDirs.each do |d|
            FileList[File.join(d, depPlatformDir, "#{Build::TargetArchitecture}", '*')].each do |f|
                # On Linux, shared objects need to go to lib/ and executables to bin/.
                # On macOS, dylibs go to Contents/Frameworks/ and executables to Contents/MacOS/
                # On Windows, :lib and :bin are the same.
                dir = File.basename(f).include?(dynamicExt) ? :lib : :bin
                installName = File.basename(f)
                # Don't brand pia-wintun.dll - it's a driver artifact, and drivers
                # aren't supported for rebranding by the brand kit.  This name is
                # hard-coded in pia-wgservice.exe.
                installName = installName.gsub('pia', Build::Brand) if installName != 'pia-wintun.dll'
                stage.install(f, dir, installName)
            end
        end

        # Include platform-specific targets.  These call stage.install() to add
        # additional installation artifacts.
        if(Build.windows?)
            PiaWindows::defineTargets(version, stage, kappsModules, commonlib, clientlib)
            PiaWindows::defineInstaller(version, stage, artifacts)
            PiaWindows::defineTools(toolsStage)
            task :default => :windeploy
        elsif(Build.macos?)
            PiaMacOS::defineTargets(version, stage, kappsModules, commonlib, clientlib)
            PiaMacOS::defineInstaller(version, stage, artifacts)
            task :default => :stage
        elsif(Build.linux?)
            PiaLinux::defineTargets(version, stage)
            PiaLinux::defineInstaller(version, stage, artifacts)
            PiaLinux::defineTools(toolsStage)
            task :default => :stage
        end

        # Define unit test targets
        PiaUnitTest.defineTargets(versionlib, deps, artifacts)

        desc "Build and stage product (suitable for directly running dev build)"
        task :stage => stage.target do |t|
            puts "staged installation"
        end

        desc "Build the product installer package"
        task :installer do |t|
            puts "built installer"
        end


        installerArtifact = artifacts.artifact("#{version.packageName}.#{Build::selectDesktop('exe', 'zip', 'run')}")
        debugSymbols = Build.new('debug-symbols')

        # Define debug artifact targets
        task :debug_collect => [debugSymbols.componentDir, stage.target,
                                installerArtifact] do |t|
            FileList[File.join(debugSymbols.componentDir, '*')].each { |f| FileUtils.rm_rf(f) }
            symbols_path = File.join(debugSymbols.componentDir, "syms")

            skipDebugSymbols = Util.selectBooleanSymbol('SKIP_DEBUG_SYMBOLS', false)
            skipQtDebugSymbols = Util.selectBooleanSymbol('SKIP_QT_DEBUG_SYMBOLS', false)
            # We can skip Qt symbols separately because some Qt installs do not have debug symbols.
            if !skipDebugSymbols && !skipQtDebugSymbols
                MakeQtSymbols.process_symbols symbols_path
            end

            if !skipDebugSymbols
                # On Windows, collect PDB symbols and the original modules, so we can use
                # them to debug dumps with WinDbg or VS.
                if(Build.windows?)
                    PiaWindows.collectSymbols(version, stage, debugSymbols)
                end

                binPath = Build.selectDesktop('', 'Contents/MacOS', 'bin')
                libPath = Build.selectDesktop('', 'Contents/Frameworks', 'lib')

                clientBin = Build.selectDesktop("#{Build::Brand}-client.exe", version.productName, "#{Build::Brand}-client")
                DumpSyms.dump_syms(File.join(stage.dir, binPath, clientBin), symbols_path)

                ["#{Build::Brand}-clientlib", "kapps_core", "kapps_net", "kapps_regions", "#{Build::Brand}-commonlib"].each do |libname|
                    lib = "#{libname}.#{Build::selectDesktop('dll', 'dylib', 'so')}"
                    DumpSyms.dump_syms(File.join(stage.dir, libPath, lib), symbols_path)
                end
                daemonBin = "#{Build::Brand}-#{Build::selectDesktop('service.exe', 'daemon', 'daemon')}"
                DumpSyms.dump_syms(File.join(stage.dir, binPath, daemonBin), symbols_path)
            end

            FileUtils.copy_entry(version.artifact('version.txt'), debugSymbols.artifact('version.txt'))
            FileUtils.copy_entry(Executable::Qt.artifact('qtversion.txt'),  debugSymbols.artifact('qtversion.txt'))
            FileUtils.copy_entry(installerArtifact,  debugSymbols.artifact(File.basename(installerArtifact)))
        end

        debugArchive = Build.new('debug-archive')
        debugArchivePkg = debugArchive.artifact("debug.zip")
        task debugArchivePkg => [debugArchive.componentDir, :debug_collect] do |t|
            Archive.zipDirectoryContents(debugSymbols.componentDir, debugArchivePkg)
        end

        desc "Build the product debug symbol package"
        task :debug => debugArchivePkg do |t|
            puts "built debug symbol package"
        end

        artifacts.install(debugArchivePkg, '')
        artifacts.install(Executable::Qt.artifact('qtversion.txt'), '')

        # Add desktop targets to :all.
        # If code coverage is available, :artifacts covers everything already, since all
        # of these targets produce artifacts.
        #
        # If coverage isn't available though, :artifacts doesn't depend on :test.
        #
        # :all is convenient to remember for use from the CLI anyway.
        task :all => [:test, :stage, :export, :installer, :debug, :compile_commands]
    end

end
