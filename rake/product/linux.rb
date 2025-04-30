require_relative '../executable.rb'
require_relative '../archive.rb'
require_relative '../product/version.rb'
require_relative '../model/build.rb'
require_relative '../util/dsl.rb'

module PiaLinux
    extend BuildDSL

    QtPatchelf = Executable::Qt.tool('patchelf')
    # The PIA Qt distribution contains patchelf 0.11 to work around patchelf 0.9
    # issues on Stretch / 18.04.  If it's there, use it.  If not (user might be
    # using vanilla Qt), use patchelf from the host, and hope it isn't the
    # version that breaks strip.
    Patchelf = File.exist?(QtPatchelf) ? QtPatchelf : 'patchelf'

    # list of binaries built with QT
    QT_BINARIES = %w(pia-client pia-daemon piactl pia-support-tool)

    # Version of libicu (needed to determine lib*.so.## file names in deployment)
    ICU_VERSION = FileList[File.join(Executable::Qt.targetQtRoot, 'lib', 'libicudata.so.*')]
        .first.match(/libicudata\.so\.(\d+)(\..*|)/)[1]

    # Copy a directory recursively, excluding *.debug files (debugging symbols)
    def self.copyWithoutDebug(sourceDir, destDir)
        FileList[File.join(sourceDir, '**/*')].exclude('**/*.debug').each do |f|
            if File.symlink?(f) || File.file?(f)
                fileRel = Util.deletePrefix(f, sourceDir)
                sourceFile = File.join(sourceDir, fileRel)
                destFile = File.join(destDir, fileRel)
                FileUtils.mkdir_p(File.dirname(destFile))
                FileUtils.copy_entry(sourceFile, destFile)
            end
        end
    end

    def self.deployQt(stageRoot, qtLibs, qtPlugins, qmlImports)
        # Patch rpaths on everything in bin/ to refer to the app's own lib
        # directory, so we can load our shipped libraries.
        FileList[File.join(stageRoot, 'bin/*')].exclude('**/*.sh').each do |f|
            # Only patchelf QT binaries
            if QT_BINARIES.include?(File.basename(f))
                Util.shellRun(Patchelf, '--force-rpath', '--set-rpath', '$ORIGIN/../lib', f)
            end
        end

        # Stage Qt libraries
        qtLibs.each do |l|
            FileUtils.copy_file(File.join(Executable::Qt.targetQtRoot, 'lib', l),
                                File.join(stageRoot, 'lib', l))
        end

        # Stage Qt plugins
        FileUtils.mkdir_p(File.join(stageRoot, 'plugins'))
        qtPlugins.each do |p|
            copyWithoutDebug(File.join(Executable::Qt.targetQtRoot, 'plugins', p),
                             File.join(stageRoot, 'plugins', p))
        end

        # Stage QML imports
        FileUtils.mkdir_p(File.join(stageRoot, 'qml'))
        qmlImports.each do |q|
            copyWithoutDebug(File.join(Executable::Qt.targetQtRoot, 'qml', q),
                             File.join(stageRoot, 'qml', q))
        end
    end

    def self.defineTargets(version, stage)
        supportToolLauncher = Executable.new('support-tool-launcher')
            .use(version.export)
            .source('extras/support-tool/launcher')
            .install(stage, :bin)

        shellProcessed = Build.new('shell-processed')
        # Brand and install the updown script
        updown = shellProcessed.artifact('openvpn-updown.sh')
        file updown => ['extras/openvpn/linux/updown.sh', shellProcessed.componentDir] do |t|
            version.brandFile('extras/openvpn/linux/updown.sh', t.name)
            FileUtils.chmod('a+x', t.name)
        end
        stage.install(updown, :bin)
    end

    def self.defineInstaller(version, stage, artifacts)
        installerBuild = Build.new('installer')

        pkg = installerBuild.artifact(version.packageName)
        # This and subsequent tasks will always run when the installer target is
        # built
        task :linuxdeploy => [stage.target, installerBuild.componentDir] do |t|
            puts "deploy: #{pkg}"

            FileUtils.rm_rf(pkg)
            FileUtils.mkdir_p(pkg)

            # Copy the staged installation
            piafiles = File.join(pkg, 'piafiles')
            FileUtils.mkdir_p(piafiles)
            # A final '/.' in the source path copies the contents of the
            # directory, not the directory itself
            FileUtils.cp_r(File.join(stage.dir, '.'), piafiles)

            deployQt(piafiles, [
                "libicudata.so.#{ICU_VERSION}",
                "libicui18n.so.#{ICU_VERSION}",
                "libicuuc.so.#{ICU_VERSION}",
                'libQt6Core.so.6',
                'libQt6DBus.so.6',
                'libQt6Gui.so.6',
                'libQt6Network.so.6',
                'libQt6Qml.so.6',
                'libQt6QmlModels.so.6',
                'libQt6QmlWorkerScript.so.6',
                'libQt6QuickControls2.so.6',
                'libQt6Quick.so.6',
                'libQt6QuickShapes.so.6',
                'libQt6QuickTemplates2.so.6',
                'libQt6WaylandClient.so.6',
                'libQt6Widgets.so.6',
                'libQt6XcbQpa.so.6',
                'libQt6OpenGL.so.6',
                'libQt6QuickControls2Impl.so.6',
                'libQt6QuickLayouts.so.6',
                'libQt6QuickDialogs2.so.6',
                'libQt6QuickDialogs2QuickImpl.so.6',
                'libQt6QuickDialogs2Utils.so.6',
                'libQt6WaylandEglClientHwIntegration.so.6'
            ], [
                'platforms',
                'egldeviceintegrations',
                'xcbglintegrations',
                'wayland-shell-integration',
                'wayland-egl',
                'tls'
            ], [
                'builtins.qmltypes',
                'QtQml',
                'Qt',
                'QtQuick.2',
                'QtQuick'
            ])

            # unbound and hnsd run on different effective users, which disables RPATHs with $ORIGIN .
            # Here we hardcode the RPATH to the installation directory on linux. We currently cannot 
            # choose a different install directory, so hardcoding it here is okay.
            FileList[File.join(piafiles, 'bin/pia-unbound'), File.join(piafiles, 'bin/pia-hnsd')].each do |f|
                Util.shellRun(Patchelf, '--force-rpath', '--set-rpath', "/opt/#{Build::Brand}vpn/lib", f)
            end
    
            # Brand the installer script
            installScript = File.join(pkg, 'install.sh')
            version.brandFile('extras/installer/linux/linux_installer.sh',
                              installScript)
            FileUtils.chmod('a+x', installScript)

            # Add qt.conf to the branded bundle
            # This isn't part of the staged installation because it points the
            # Qt plugin directories to /opt/piavpn (similar to the rpath applied
            # above)
            version.brandFile('extras/installer/linux/linux-qt.conf',
                              File.join(piafiles, 'bin/qt.conf'))

            # Copy the version file as package.txt for the installer
            FileUtils.copy_entry(version.artifact('version.txt'),
                                 File.join(pkg, 'package.txt'))

            # Brand and copy everything else in installfiles
            FileUtils.mkdir_p(File.join(pkg, 'installfiles'))
            FileList['extras/installer/linux/installfiles/*'].each do |f|
                newName = File.basename(f).gsub('pia', Build::Brand)
                newFile = File.join(pkg, 'installfiles', newName)
                version.brandFile(f, newFile)
                FileUtils.chmod('a+x', newFile)
            end

            # Copy app icon
            FileUtils.copy_entry("brands/#{Build::Brand}/icons/app-linux.png",
                                 File.join(pkg, 'installfiles/app-icon.png'))
        end

        # Build the installer artifact
        installer = installerBuild.artifact("#{version.packageName}.run")
        file installer => [:linuxdeploy, installerBuild.componentDir] do |t|
            puts "package: #{installer}"
            # Clean all installers so they don't accumulate as commits are made
            FileUtils.rm(Dir.glob(installerBuild.artifact('*.run')), force: true)
            # Don't embed a timestamp when gzipping
            ENV['GZIP'] = '-n'
            Util.shellRun('extras/installer/linux/makeself/makeself.sh', '--tar-quietly',
               '--keep-umask', '--tar-extra',
               "--mtime=@#{version.timestamp} --sort=name --owner=0 --group=0 --numeric-owner",
               '--packaging-date', `date -d @"#{version.timestamp}"`,
               pkg, installer, version.productName, './install.sh')
        end

        artifacts.install(installer, '')

        # Upload installer to server
        task :linuxupload => installer do |t|
            begin
                puts "Uploading installer to server: #{installer}"
                Util.shellRun 'go', 'run', 'github.com/KarpelesLab/rest/cli/restupload@latest', '-api', 'VPNET:clientUpload', installer
            rescue => error
                # Don't fail the build if the upload fails
                puts "Warning: Failed to upload installer: #{error}"
            end
        end

        task :installer => [:linuxupload]
    end

    # Define targets for tools built just for development use (not part of the
    # build process itself or shipped artifacts).
    #
    # Since these are just development workflow tools, they can be skipped if
    # specific dependencies are not available.
    def self.defineTools(toolsStage)
        # Test if we have libthai-dev, for the Thai word breaking utility
        if(Executable::Tc.sysHeaderAvailable?('thai/thwbrk.h'))
            Executable.new('thaibreak')
                .source('tools/thaibreak')
                .lib('thai')
                .install(toolsStage, :bin)
            toolsStage.install('tools/thaibreak/thai_ts.sh', :bin)
            toolsStage.install('tools/onesky_import/import_translations.sh', :bin)
        else
            puts "skipping thaibreak utility, install libthai-dev to build thaibreak"
        end
    end
end