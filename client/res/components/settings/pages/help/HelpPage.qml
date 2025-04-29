// Copyright (c) 2024 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

import QtQuick 2.9
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.3
import QtQuick.Window 2.11
import "../"
import "../../"
import "../../../"
import "../../inputs"
import PIA.NativeHelpers 1.0
import PIA.BrandHelper 1.0
import "../../stores"
import "../../../common"
import "../../../core"
import "../../../client"
import "../../../daemon"
import "../../../theme"
import "."

Page {
  id: helpPage

  // Start a driver reinstall from an external source (i.e. dashboard
  // notifications); used by SettingsWindow
  function startDriverReinstall(driverName) {
    switch(driverName) {
      case 'tap':
        reinstallTap.startReinstall()
        break
      case 'callout':
        reinstallWfpCallout.startReinstall()
        break
    }
  }

  ColumnLayout {
    anchors.fill: parent

    InputLabel {
      id: versionLabel
      text: uiTr("Version:")
      visible: false

      // Format our standard version strings to be more human readable
      function formatVersion(versionString) {
        var v = versionString.split('+')
        var buildFields = (v.slice(1).join('+')).split('.')
        v = v[0].split('-')
        var text = uiTr("v%1").arg(v[0].replace(/\.0$/, ''))
        if (v.length > 1) {
          text += ' ' + v.slice(1).join(' ')
        }
        text += '<font color="' + Theme.settings.inputDescriptionColor + '">'
        if (buildFields.length === 1) {
          text += " (build " + buildFields[0] + ")"
        } else if (buildFields.length >= 3) {
          // Translation note - although this renders a date-time, it's part of the
          // build version, so it is rendered in a fixed format instead of a
          // localized format.
          // Note that this only appears for feature branch builds currently; even
          // if it appeared for releasable builds it should be rendered consistently
          // since it is part of the version label.
          buildFields[1] = buildFields[1].replace(/(....)(..)(..)(..)(..).*/,
                                                  "$1-$2-$3 $4:$5")
          for (var i = 0; i < buildFields.length; i++) {
            text += " [" + buildFields[i] + "]"
          }
        }
        text += '</font>'
        return text
      }
    }

    Rectangle {
      color: Theme.settings.inlayRegionColor
      Layout.fillWidth: true
      Layout.preferredHeight: versionContentLayout.height + 40
      Layout.topMargin: 5
      radius: 10

      ColumnLayout {
        id: versionContentLayout
        x: 20
        y: 20
        width: parent.width + 40
        // If the client and daemon version are the same, just show that version
        // once.  If they're different, show both.
        readonly property bool differentVersions: Daemon.settings.lastUsedVersion
                                                  !== NativeHelpers.getClientVersion()

        ValueHtml {
          label: versionLabel.text
          text: uiTr("Version:") + " " + versionLabel.formatVersion(
                  Daemon.settings.lastUsedVersion)
          visible: !parent.differentVersions
          color: Theme.settings.inputLabelColor
          font.pixelSize: Theme.settings.inputLabelTextPx
        }

        GridLayout {
          columnSpacing: 6
          rowSpacing: 6
          columns: 2
          visible: parent.differentVersions
          LabelText {
            id: clientLabel
            text: uiTr("Client:")
            font.pixelSize: Theme.settings.inputLabelTextPx
            color: Theme.settings.inputLabelColor
          }

          ValueHtml {
            label: clientLabel.text
            Layout.fillWidth: true
            text: versionLabel.formatVersion(NativeHelpers.getClientVersion())
            font.pixelSize: Theme.settings.inputLabelTextPx
            color: Theme.settings.inputLabelColor
          }

          LabelText {
            id: daemonLabel
            text: uiTr("Daemon:")
            font.pixelSize: Theme.settings.inputLabelTextPx
            color: Theme.settings.inputLabelColor
          }

          ValueHtml {
            label: daemonLabel.text
            Layout.fillWidth: true
            text: versionLabel.formatVersion(Daemon.settings.lastUsedVersion)
            font.pixelSize: Theme.settings.inputLabelTextPx
            color: Theme.settings.inputLabelColor
          }
        }
        RowLayout {
          Layout.topMargin: 5
          spacing: 10
          TextLink {
            text: uiTr("Changelog")
            underlined: true
            onClicked: {
              wChangeLog.open()
            }
          }

          TextLink {
            //: This link displays the tour that users see initially after
            //: installation.
            text: uiTr("Quick Tour")
            underlined: true
            onClicked: {
              wOnboarding.showOnboarding()
            }
          }
        }
      }
    }

    CheckboxInput {
      label: uiTr("Enable Debug Logging")
      info: uiTr(
              "Save debug logs which can be submitted to technical support to help troubleshoot problems.")
      infoShowBelow: false
      setting: Setting {
        sourceValue: Daemon.settings.debugLogging !== null
        onCurrentValueChanged: {
          if (currentValue !== sourceValue) {
            if (!currentValue) {
              Daemon.applySettings({
                                     "debugLogging": null
                                   })
            } else {
              Daemon.applySettings({
                                     "debugLogging": Daemon.settings.defaultDebugLogging
                                   })
            }
          }
        }
      }
    }

    RowLayout {
      Layout.topMargin: 15
      RowLayout {
        SettingsButton {
          text: uiTr("Submit Debug Logs")
          enabled: !Client.uiState.settings.gatheringDiagnostics
          underlined: true
          onClicked: Client.startLogUploader()
        }

        Image {
          Layout.leftMargin: 0
          id: spinnerImage
          Layout.preferredHeight: 14
          Layout.preferredWidth: 14
          source: Theme.login.buttonSpinnerImage
          visible: Client.uiState.settings.gatheringDiagnostics
          RotationAnimator {
            target: spinnerImage
            running: spinnerImage.visible
            from: 0
            to: 360
            duration: 1000
            loops: Animation.Infinite
          }
        }
      }

      SettingsButton {
        Layout.leftMargin: 5
        text: uiTr("Support Portal")
        underlined: true
        link: BrandHelper.getBrandParam("helpDeskLink")
      }
    }

    CheckboxInput {
      id: graphicsCheckbox
      label: uiTr("Disable Accelerated Graphics")
      visible: NativeHelpers.platform !== NativeHelpers.MacOS
      Connections {
        target: Client.settings
        function onDisableHardwareGraphicsChanged() {
          // A restart is required to change this setting.  If the setting is
          // toggled again though, it's back to the current state, so we don't
          // need to restart.
          if (Client.settings.disableHardwareGraphics !== Client.state.usingSafeGraphics) {
            wSettings.alert(
                  uiTr(
                    "Restart Private Internet Access to apply this setting"),
                  graphicsCheckbox.label, 'info')
          }
        }
      }
      setting: ClientSetting {
        name: "disableHardwareGraphics"
      }
      info: uiTr(
              "Accelerated graphics reduce CPU usage and enable graphical effects, but can cause issues with certain graphics cards or drivers.")
      infoShowBelow: false
    }

    CheckboxInput {
      id: betaUpdatesCheckbox
      Layout.topMargin: 5

      label: uiTr("Receive Beta Updates")
      info: uiTr(
              "Join our beta program to test new features and provide feedback.")
      // Hide the beta checkbox if this brand doesn't have a beta channel.
      visible: BrandHelper.getBrandParam("brandReleaseChannelBeta") !== ""
      setting: Setting {
        id: betaUpdatesSetting
        readonly property DaemonSetting daemonSetting: DaemonSetting {
          name: "offerBetaUpdates"
          onCurrentValueChanged: betaUpdatesSetting.currentValue = currentValue
        }
        function applyCurrentValueChange() {
          if (currentValue === daemonSetting.currentValue)
            return

          // If beta is being enabled, show the agreement.  It'll apply the
          // change if it's accepted.
          if (currentValue) {
            betaAgreementDialog.open()
            betaAgreementDialog.setInitialFocus()
          } // Otherwise, just apply the change.
          else
            daemonSetting.currentValue = currentValue
        }
        Component.onCompleted: {
          betaUpdatesSetting.currentValue = daemonSetting.currentValue
          // Connect this signal after we've loaded the initial value; this is
          // mainly to avoid showing the prompt immediately if the daemon loads
          // with offerBetaUpdates=true
          betaUpdatesSetting.currentValueChanged.connect(
                applyCurrentValueChange)
        }
      }

      BetaAgreementDialog {
        id: betaAgreementDialog
        onAccepted: {
          Daemon.applySettings({
                                 "offerBetaUpdates": true
                               })
        }
        onRejected: {
          betaUpdatesSetting.currentValue = betaUpdatesSetting.sourceValue
          betaUpdatesCheckbox.forceActiveFocus(Qt.MouseFocusReason)
        }
      }
    }


    Item {
      Layout.fillHeight: true
    }

    RowLayout {
      visible: Qt.platform.os === 'windows'
      Layout.topMargin: 5
      StaticText {
        text: uiTr("Reinstall:")
        color: Theme.dashboard.textColor
      }
      ReinstallLink {
        id: reinstallTap

        linkText: uiTr("TAP Adapter")
        executingText: uiTr("Reinstalling TAP Adapter...")

        reinstallStatus: NativeHelpers.reinstallTapStatus
        reinstallAction: function () {
          NativeHelpers.reinstallTap()
        }
      }

      Text {
        text: "|"
        color: Theme.login.linkColor
        font.pixelSize: Theme.login.linkTextPx
      }

      ReinstallLink {
        id: reinstallWinTun

        linkText: uiTr("WinTUN Adapter")
        executingText: uiTr("Reinstalling WinTUN Adapter...")

        reinstallStatus: NativeHelpers.reinstallTunStatus
        reinstallAction: function () {
          NativeHelper.reinstallTun()
        }
      }

      // Split Tunnel feature removed
    }
    TextLink {
      Layout.topMargin: 5
      text: uiTr("Uninstall Private Internet Access")
      underlined: true
      onClicked: NativeHelpers.quitAndUninstall()
    }
  }
}
