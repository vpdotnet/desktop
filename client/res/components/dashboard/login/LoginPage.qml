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

import QtQuick 2.15
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.3
import "../../../javascript/app.js" as App
import "../../daemon"
import "../../theme"
import "../../common"
import "../../core"
import PIA.Error 1.0
import PIA.FlexValidator 1.0
import PIA.BrandHelper 1.0
import PIA.NativeHelpers 1.0

FocusScope {
  // Whether we display an error, and if we do, what error it is.
  readonly property var errors: {
    'none': 0,
    'auth': 1,
    'rate': 2, // Rate limited
    'api': 3,  // Error reaching API, etc. (user's creds might be correct)
    'unknown': 4,
    'email_sent': 5,
    'expired': 6  // The user's subscription has expired
  }
  property int shownError: errors.none
  property int emailError: errors.none
  property int tokenError: errors.none
  property bool hasValidInput: loginInput.text.length > 0 && passwordInput.text.length > 0
  property bool loginInProgress: false
  property bool emailRequestInProgress: false
  readonly property int pageHeight: 400
  readonly property int maxPageHeight: pageHeight
  readonly property bool emailLoginFeatureEnabled: Daemon.data.flags.includes("email_login")

  property real retryAfterTime: 0

  // The current time which can be updated by a timer
  property real currentTime: 0

  // A timer that always updates the current time once every second
  // because we cannot have the current time automatically updated
  Timer {
    onTriggered: {
      currentTime = Date.now();
    }
    repeat: true
    interval: 1000
    running: retryAfterTime > 0 && retryAfterTime + 2000 > currentTime
  }



  // The login page can be in one of multiple distinct modes:
  //
  // - login: For a regular email/password login.
  // - email: Form to allow user to request email login link
  // - token: A spinner which is displayed while the token validation is being performed
  readonly property var modes: {
    'login': 0,
    'email': 1,
    'token': 2,
  }
  property int mode: 1

  function resetLoginPage (newMode) {
    newMode = newMode || modes.email;
    shownError = errors.none
    emailError = errors.none
    tokenError = errors.none
    loginInProgress = false
    emailRequestInProgress = false
    emailInput.text = ""
    mode = newMode
  }

  function requestEmailLogin () {
    if(emailInput.text.length > 0 && !emailRequestInProgress) {
      emailRequestInProgress = true
      emailError = errors.none

      Daemon.emailLogin(emailInput.text, function(error) {
        emailRequestInProgress = false
        if (error) {
          switch(error.code) {
          default:
            emailError = errors.unknown
            break
          }
          console.warn('Email token request failed:', error);
        } else {
          emailError = errors['email_sent']
        }
      });
    }
  }

  // Contains both the normal 'login' page and the 'upgrade required' page (if the user's account expired)
  StackLayout {
    id: stateStack
    readonly property int loginPageIndex: 0
    readonly property int upgradePageIndex: 1
    property int activeIndex: loginPageIndex
    anchors.fill: parent
    currentIndex: activeIndex

    // Default page
    function showLoginPage() {
      stateStack.activeIndex = loginPageIndex
    }

    // Shown when the user's subscription expires
    function showUpgradePage() {
      stateStack.activeIndex = upgradePageIndex
    }

    // The "login" page (everything contained in this Rectangle)
    Rectangle {
      color: "transparent"
      clip: true
      Item {
        id: mapContainer
        width: parent.width
        height: loginContent.y

        LocationMap {
          id: mapImage
          anchors.horizontalCenter: parent.horizontalCenter
          // Size to 130px tall as long as the minimum margin is available (14 px)
          height: Math.min(parent.height - 14, 130)
          width: {
            console.info("map size: " + 2*height + "x" + height)
            return 2*height
          }
          // Distribute the margin mostly on the top - 36:10 top/bottom
          y: (parent.height - height) * 36 / 46
          mapOpacity: Theme.login.mapOpacity
          markerInnerRadius: 3.5
          markerOuterRadius: 6.5
          location: Daemon.state.vpnLocations.nextLocation
        }
      }


      Item {
        id: loginContent
        anchors.bottom: linkContainer.top
        anchors.bottomMargin: 20
        anchors.left: parent.left
        width: parent.width
        height: usernameModeContent.height

        //
        // "Email Login" page
        //
        Item {
          visible: mode === modes.email
          anchors.fill: parent

          Text {
            color: {
              switch(emailError) {
              case errors.email_sent:
                return Theme.login.inputTextColor
              default:
                return Theme.login.errorTextColor
              }
            }
            text: {
              switch(emailError) {
              case errors.unknown:
                return uiTr("Something went wrong. Please try again later.")
              case errors.email_sent:
                return uiTr("Please check your email.")
              default:
                return ""
              }
            }
            anchors.top: parent.top
            anchors.horizontalCenter: parent.horizontalCenter
            font.pixelSize: Theme.login.errorTextPx
            visible: emailError !== errors.none
          }

          LoginText {
            id: emailInput
            errorState: emailError !== errors.none && emailError !== errors.email_sent
            anchors.horizontalCenter: parent.horizontalCenter
            width: 260
            anchors.top: parent.top
            anchors.topMargin: 16
            placeholderText: uiTr("Email Address")
            onAccepted: requestEmailLogin()
            validator: RegularExpressionValidator {
              regularExpression: /^\S+@\S+\.\S+$/
            }
          }

          LoginButton {
            id: sendEmailButton
            buttonText: uiTr("SEND EMAIL")
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.bottom: parent.bottom
            loginEnabled: emailInput.text.length > 0 && emailInput.acceptableInput
            loginWorking: emailRequestInProgress
            onTriggered: requestEmailLogin()
          }
        }

        // When logging in with a token
        Item {
          visible: mode === modes.token
          anchors.fill: parent

          Image {
            id: spinnerImage
            height: 40
            width: 40
            source: Theme.login.buttonSpinnerImage
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: 40

            RotationAnimator {
              target: spinnerImage
              running: spinnerImage.visible
              from: 0;
              to: 360;
              duration: 1000
              loops: Animation.Infinite
            }

            visible: tokenError === errors.none
          }

          Text {
            color: {
              if(tokenError !== errors.none)
                return Theme.login.errorTextColor
              else
                return Theme.dashboard.textColor
            }
            anchors.top: spinnerImage.bottom
            anchors.topMargin: 15
            anchors.horizontalCenter: parent.horizontalCenter
            text: {
              if(tokenError === errors.none) {
                return uiTr("Please Wait...")
              } else {
                return uiTr("Something went wrong. Please try again later.")
              }
            }
          }
        }


      }

      Item {
        id: linkContainer
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 24
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: 20
        anchors.rightMargin: 20

        height: buyAccount.y + buyAccount.height

        // Normally, put the last two links side-by-side:
        //
        // | Log in with Email                   |
        // | Forgot Password         Buy Account |
        // +-------------------------------------+
        //
        // For long translations, stack the last two links instead
        //
        // | Log in with Email translation       |
        // | Forgot password translation         |
        // | Buy Account translation             |
        // +-------------------------------------+
        //
        // This layout also ensures that the "login mode" link always gets a full
        // line; the translations for this line vary quite a bit and we don't want
        // the layout to change when the login mode changes.
        readonly property int minimumHorzGap: 4
        readonly property int stackedGap: 4
        readonly property bool stackLinks: {
          return forgotPassword.implicitWidth + buyAccount.implicitWidth + minimumHorzGap > linkContainer.width
        }

        TextLink {
          id: loginMode
          x: 0
          y: 0
          visible: false // emailLoginFeatureEnabled
          text: {
            if(mode === modes.login)
              return uiTr("Log in with Email")
            else if(mode === modes.email)
              return uiTr("Log in with Username")
            else if(mode === modes.token)
              return uiTr("Log in with Username")
          }
          onClicked: {
            if(mode === modes.login)
              resetLoginPage(modes.email)
            else if(mode === modes.email)
              resetLoginPage(modes.login)
            else if(mode === modes.token)
              resetLoginPage(modes.login)
          }
        }

        TextLink {
          id: buyAccount
          x: linkContainer.stackLinks ? 0 : parent.width - width
          y: {
            var y = forgotPassword.y
            if(linkContainer.stackLinks)
              y += forgotPassword.height + linkContainer.stackedGap
            return y
          }
          text: uiTr("Buy Account")
          link: BrandHelper.getBrandParam("buyAccountLink")
        }
      }
    }

    // The "upgrade required" page - shown when the user's subscription has expired
    Item {
     id: upgradeRequired

      Image {
        id: upgradeRocket
        source: Theme.login.upgradeRocketImage
        height: 135
        width: (height / sourceSize.height) * sourceSize.width
        anchors.top: parent.top
        anchors.topMargin: 15
        anchors.horizontalCenter: parent.horizontalCenter
      }

     Text {
       id: upgradeText
       visible: true
       color: Theme.dashboard.textColor
       text: uiTr("Welcome Back!")
       font.pointSize: 15
       font.weight: Font.Bold
       anchors.top: upgradeRocket.bottom
       anchors.topMargin: 10
       anchors.horizontalCenter: parent.horizontalCenter
     }

     Text {
       id: upgradeMessageText
       visible: true
       color: Theme.dashboard.textColor
       width: upgradeRequired.width * 0.90
       text: uiTr("In order to use Private Internet Access, you'll need to renew your subscription.")
       wrapMode: Text.WordWrap
       horizontalAlignment: Text.AlignHCenter
       anchors.horizontalCenter: parent.horizontalCenter
       anchors.top: upgradeText.top
       anchors.topMargin: 50
     }

     LoginButton {
       id: upgradeButton
       buttonText: uiTr("RENEW NOW")
       anchors.horizontalCenter: parent.horizontalCenter
       anchors.top: upgradeMessageText.bottom
       anchors.topMargin: 35
       loginEnabled: true
       loginWorking: false
       onTriggered: {
         Qt.openUrlExternally(BrandHelper.getBrandParam("subscriptionLink"))
       }
     }

     TextLink {
       id: backToLoginLink
       text: uiTr("Back to login")
       anchors.top: upgradeButton.bottom
       anchors.topMargin: 20
       anchors.horizontalCenter: parent.horizontalCenter
       underlined: true
       onClicked: {
         stateStack.showLoginPage()
       }
     }
   }
  }

  function resetCreds() {
    loginInput.text = Daemon.account.username
    passwordInput.text = ""
  }

  // If the daemon updates its credentials (mainly for a logout), reset the
  // credentials in the login page
  Connections {
    target: Daemon.account
    function onUsernameChanged() {
      resetCreds()
    }
  }

  Connections {
    target: NativeHelpers
    function onUrlOpenRequested(path, query) {
      if(path === "login" && query.token && query.token.length > 0 && !Daemon.account.loggedIn) {
        mode = modes.token
        tokenError = errors.none

        Daemon.setToken(query.token, function (error) {
          if(error) {
            switch(error.code) {
            default:
              tokenError = errors.unknown
              break
            }
          } else {
            // reset the mode to email mode
            mode = modes.email
            tokenError = errors.none;
          }
        })
      }
    }
  }

  Connections {
    target: Daemon.account
    function onLoggedInChanged() {
      if(Daemon.account.loggedIn) {
        resetLoginPage();
      }
    }
  }

  function onEnter () {
    console.log('login onEnter')
    headerBar.logoCentered = false
    headerBar.needsBottomLine = false

    // Clear loginInProgress in case it was set by a prior login (it stays set
    // during the transition)
    loginInProgress = false
    shownError = errors.none
  }

  Component.onCompleted: {
    console.log('login onCompleted')
    // Load the initial stored credentials
    resetCreds()
  }
}
