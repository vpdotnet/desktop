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
import "../../inputs"
import PIA.NativeHelpers 1.0
import PIA.BrandHelper 1.0
import "../../stores"
import "../../../core"
import "../../../common"
import "../../../client"
import "../../../daemon"
import "../../../theme"
import "."

Page {
  ColumnLayout {
    visible: Daemon.account.loggedIn
    anchors.fill: parent
    anchors.leftMargin: Theme.settings.narrowPageLeftMargin
    anchors.rightMargin: Theme.settings.narrowPageLeftMargin
    spacing: 6

    StaticText{
      color: Theme.settings.inputLabelColor
      font.bold: true
      font.pixelSize: Theme.settings.inputLabelTextPx
      id: usernameLabel
      text: uiTr("Username")
    }

    Rectangle {
      color: Theme.settings.inlayRegionColor
      Layout.fillWidth: true
      Layout.preferredHeight: 70
      radius: 10
      RowLayout {
        anchors.fill: parent
        anchors.margins: 20

        ValueText {
          text: Daemon.account.username
          label: usernameLabel.text
          color: Theme.settings.inputLabelColor
          font.pixelSize: Theme.settings.inputLabelTextPx
          font.bold: true
        }

        Item {
          Layout.fillWidth: true
        }

        SettingsButton {
          text: uiTr("Manage My Account")
          underlined: true
          link: BrandHelper.getBrandParam("manageAccountLink")
        }
        SettingsButton {
          text: uiTr("Log Out / Switch Account")
          underlined: true
          onClicked: Daemon.logout()
        }
      }
    }

    // Spacer between groups
    Item {
      width: 1
      height: 4
    }

    StaticText {
      font.bold: true
      color: Theme.settings.inputLabelColor
      font.pixelSize: Theme.settings.inputLabelTextPx
      id: subscriptionLabel
      text: uiTr("Subscription")
    }

    Rectangle {
      color: Theme.settings.inlayRegionColor
      Layout.fillWidth: true
      Layout.preferredHeight: 80
      radius: 10
      RowLayout {
        anchors.fill: parent
        anchors.margins: 20

        ValueHtml {
          label: subscriptionLabel.text
          text: {
            var text = Daemon.account.planName
                || '<font color="%1">%2</font>'.arg(
                  Theme.settings.inputDescriptionColor).arg("---")
            if (Daemon.account.expired && !Daemon.account.needsPayment) {
              text = '<font color="%1">%2</font>'.arg(
                    Theme.dashboard.notificationErrorLinkColor).arg(
                    uiTr("Expired"))
            }
            if (Daemon.account.expirationTime) {
              var linkColor = Daemon.account.expired ? Theme.dashboard.notificationErrorLinkColor : Theme.settings.inputDescriptionColor

              var linkMsg
              if (Daemon.account.expired)
                linkMsg = uiTr("(expired on %1)")
              else if (Daemon.account.recurring)
                linkMsg = uiTr("(renews on %1)")
              else
                linkMsg = uiTr("(expires on %1)")

              var expDate = new Date(Daemon.account.expirationTime)
              var expDateStr = expDate.toLocaleString(
                    Qt.locale(),
                    Locale.ShortFormat)
              linkMsg = linkMsg.arg(expDateStr)

              text += '<br/> <font color="%1">%2</font>'.arg(
                    linkColor).arg(linkMsg)
            }
            return text
          }
          color: Theme.settings.inputLabelColor
          font.pixelSize: Theme.settings.inputLabelTextPx
        }

        Item {
          Layout.fillWidth: true
        }

        SettingsButton {
          text: Daemon.account.plan === 'trial' ? uiTr(
                                                    "Purchase Subscription") : Daemon.account.recurring ? uiTr("Manage Subscription") : uiTr("Renew Subscription")
          underlined: true
          visible: (Daemon.account.expireAlert
                    || Daemon.account.plan === 'trial')
                   && Daemon.account.renewURL !== ''
                   && BrandHelper.brandCode === 'pia'
          link: Daemon.account.renewURL
        }
      }
    }

    // Vertical spacer
    Item {
      Layout.fillHeight: true
      width: 1
    }
  }

  ColumnLayout {
    visible: !Daemon.account.loggedIn
    anchors.fill: parent
    anchors.leftMargin: Theme.settings.narrowPageLeftMargin
    anchors.rightMargin: Theme.settings.narrowPageLeftMargin
    spacing: 6
    Rectangle {
      Layout.columnSpan: 2
      Layout.fillWidth: true
      Layout.preferredHeight: 280
      Layout.topMargin: 5
      color: Theme.settings.inlayRegionColor
      radius: 20

      Rectangle {
        id: loginIcon
        anchors.horizontalCenter: parent.horizontalCenter
        width: 60
        height: 60
        anchors.top: parent.top
        anchors.topMargin: 40
        radius: 30
        color: "transparent"
        border.color: Theme.settings.vbarTextColor
        opacity: 0.2

        Image {
          anchors.centerIn: parent
          // Use the active state for dark theme, inactive for light theme
          source: Theme.dark ? Theme.settings.pageImages['account'][0] : Theme.settings.pageImages['account'][1]
          width: 40
          height: 40
        }
      }

      StaticText {
        id: loginHeadline
        text: uiTr("You're not logged in")
        color: Theme.settings.vbarTextColor
        opacity: 0.7
        font.pixelSize: 22
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: loginIcon.bottom
        anchors.topMargin: 20
      }

      StaticText {
        id: loginText
        text: uiTr(
                "To view your account details, please log in to your account")
        color: Theme.settings.vbarTextColor
        opacity: 0.6
        font.pixelSize: 14
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: loginHeadline.bottom
        anchors.topMargin: 6
      }

      SettingsButton {
        id: loginButton
        text: uiTr("Log in to your account")
        anchors.top: loginText.bottom
        anchors.topMargin: 20
        anchors.horizontalCenter: parent.horizontalCenter
        onClicked: {
          dashboard.window.showDashboard(trayManager.getIconMetrics())
        }
      }
    }

    Item {
      Layout.fillHeight: true
    }
  }
}