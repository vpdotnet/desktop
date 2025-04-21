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
  property bool hasValidInput: (mode === modes.email && emailInput.text.length > 0 && emailInput.acceptableInput) 
                           || (mode === modes.token && tokenInput.text.length > 0)
  property bool loginInProgress: false
  property bool emailRequestInProgress: false
  property bool tokenValidationInProgress: false
  readonly property int pageHeight: 400
  readonly property int maxPageHeight: pageHeight
  readonly property bool emailLoginFeatureEnabled: true // Always enabled as this is the only login method now

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



  // The login page can be in one of two modes:
  //
  // - email: Form to allow user to request email login
  // - token: Form to input the token received via email
  readonly property var modes: {
    'email': 0,
    'token': 1,
  }
  property int mode: 0 // Default to email mode
  property string lastEmail: "" // Store the last email used to request a token

  function resetLoginPage (newMode) {
    newMode = newMode || modes.email;
    shownError = errors.none
    emailError = errors.none
    tokenError = errors.none
    loginInProgress = false
    emailRequestInProgress = false
    tokenValidationInProgress = false
    emailInput.text = ""
    tokenInput.text = ""
    lastEmail = ""
    mode = newMode
  }
  
  function validateToken() {
    if(tokenInput.text.length > 0 && !tokenValidationInProgress) {
      tokenValidationInProgress = true
      tokenError = errors.none
      
      console.log('Validating token for email:', lastEmail);
      
      Daemon.setToken(tokenInput.text, function(error) {
        tokenValidationInProgress = false
        if (error) {
          console.error('Token validation failed. Error code:', error.code, 'Error message:', error.message);
          
          // Display a more useful error message based on the error
          switch(error.code) {
            case NativeError.ApiUnauthorizedError:
              tokenError = errors.auth
              break
            case NativeError.ApiRateLimitedError:
              tokenError = errors.rate
              break
            case NativeError.ApiNetworkError:
              tokenError = errors.api
              break
            default:
              tokenError = errors.unknown
              break
          }
        } else {
          console.log('Token validation succeeded. User now logged in.');
          resetLoginPage(modes.email)
        }
      });
    }
  }

  function requestEmailLogin () {
    if(emailInput.text.length > 0 && !emailRequestInProgress) {
      emailRequestInProgress = true
      emailError = errors.none

      console.log('Requesting email login for:', emailInput.text);
      
      // Log Daemon state for debugging
      console.log('Daemon connected:', Daemon.connected);
      console.log('Daemon state connectionState:', Daemon.state.connectionState);
      
      Daemon.emailLogin(emailInput.text, function(error) {
        emailRequestInProgress = false
        if (error) {
          console.error('Email token request failed. Error code:', error.code, 'Error message:', error.message);
          console.log('Full error object:', JSON.stringify(error));
          
          // Display a more useful error message based on the error
          switch(error.code) {
          case NativeError.ApiUnauthorizedError:
            emailError = errors.auth
            break
          case NativeError.ApiRateLimitedError:
            emailError = errors.rate
            break
          case NativeError.ApiNetworkError:
            // Added specific API network error handling
            emailError = errors.api
            console.error('Network error details: Unable to reach API server - check connection');
            // Check daemon connection status
            console.log('Is daemon connected?', Daemon.connected);
            break
          case NativeError.ApiNotFoundError:
            console.error('API endpoint not found (404) - The login_link endpoint may not exist on the server');
            emailError = errors.api
            break
          case NativeError.ApiServerError:
            console.error('Server error (5xx) - The server is experiencing issues');
            emailError = errors.api
            break
          default:
            console.error('Unknown error type, code:', error.code);
            emailError = errors.unknown
            break
          }
        } else {
          console.log('Email login request succeeded. Check your email for the login token.');
          lastEmail = emailInput.text
          emailError = errors.none
          mode = modes.token_input
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
        height: Math.min(parent.height * 0.4, 150) // Take up to 40% of height or max 150px
        anchors.top: parent.top

        LocationMap {
          id: mapImage
          anchors.horizontalCenter: parent.horizontalCenter
          anchors.centerIn: parent
          height: Math.min(parent.height - 14, 130)
          width: {
            console.info("map size: " + 2*height + "x" + height)
            return 2*height
          }
          mapOpacity: Theme.login.mapOpacity
          markerInnerRadius: 3.5
          markerOuterRadius: 6.5
          location: Daemon.state.vpnLocations.nextLocation
        }
      }


      Item {
        id: loginContent
        anchors.centerIn: parent
        width: parent.width
        height: childrenRect.height
        anchors.verticalCenterOffset: 20 // Move slightly downward from exact center

        //
        // "Email Login" page
        //
        Column {
          id: emailLoginItem
          visible: mode === modes.email
          width: parent.width
          spacing: 20
          anchors.centerIn: parent

          Text {
            anchors.horizontalCenter: parent.horizontalCenter
            text: uiTr("Enter your email to log in")
            color: Theme.dashboard.textColor
            font.pixelSize: 16
            font.weight: Font.Medium
          }

          Text {
            id: emailErrorText
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
              case errors.auth:
                return uiTr("Authentication error - check your email address")
              case errors.rate:
                return uiTr("Too many login attempts. Please try again later.")
              case errors.api:
                return uiTr("Network error - Can't reach the server")
              case errors.email_sent:
                return uiTr("Please check your email.")
              default:
                return ""
              }
            }
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: Theme.login.errorTextPx
            visible: emailError !== errors.none
          }

          LoginText {
            id: emailInput
            errorState: emailError !== errors.none && emailError !== errors.email_sent
            anchors.horizontalCenter: parent.horizontalCenter
            width: 260
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
            loginEnabled: emailInput.text.length > 0 && emailInput.acceptableInput
            loginWorking: emailRequestInProgress
            onTriggered: requestEmailLogin()
          }
        }

        // Token input page
        Column {
          id: tokenLoginItem
          visible: mode === modes.token
          width: parent.width
          spacing: 20
          anchors.centerIn: parent

          Text {
            anchors.horizontalCenter: parent.horizontalCenter
            text: lastEmail ? uiTr("Enter the token sent to %1").arg(lastEmail) : uiTr("Enter the token from your email")
            color: Theme.dashboard.textColor
            width: parent.width * 0.8
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            font.pixelSize: 16
            font.weight: Font.Medium
          }

          Text {
            id: tokenErrorText
            color: Theme.login.errorTextColor
            text: {
              switch(tokenError) {
                case errors.unknown:
                  return uiTr("Something went wrong. Please try again.")
                case errors.auth:
                  return uiTr("Invalid token. Please check and try again.")
                case errors.rate:
                  return uiTr("Too many attempts. Please try again later.")
                case errors.api:
                  return uiTr("Network error - Can't reach the server")
                default:
                  return ""
              }
            }
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: Theme.login.errorTextPx
            visible: tokenError !== errors.none
          }

          LoginText {
            id: tokenInput
            errorState: tokenError !== errors.none
            anchors.horizontalCenter: parent.horizontalCenter
            width: 260
            placeholderText: uiTr("Token")
            onAccepted: validateToken()
          }

          LoginButton {
            id: validateTokenButton
            buttonText: uiTr("LOG IN")
            anchors.horizontalCenter: parent.horizontalCenter
            loginEnabled: tokenInput.text.length > 0
            loginWorking: tokenValidationInProgress
            onTriggered: validateToken()
          }
          
          TextLink {
            id: backToEmailLink
            text: uiTr("Back to email form")
            anchors.horizontalCenter: parent.horizontalCenter
            font.pixelSize: 12
            onClicked: {
              resetLoginPage(modes.email)
            }
          }
        }


      }

      Item {
        id: linkContainer
        anchors.top: loginContent.bottom
        anchors.topMargin: 20
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: 20
        anchors.rightMargin: 20
        height: buyAccount.height

        TextLink {
          id: buyAccount
          anchors.horizontalCenter: parent.horizontalCenter
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
    emailInput.text = ""
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
        // Auto-fill the token input and switch to token mode
        tokenInput.text = query.token
        tokenError = errors.none
        mode = modes.token
        
        // Optionally, auto-validate the token immediately
        validateToken()
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
