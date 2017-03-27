# Pushbullet plugin for Pidgin

Lets you (currently) send/receive SMS from your Android phone to/from Pidgin

The plugin is a work in progress and is a bit rough around the edges at the moment, but for now use your Access Token from https://www.pushbullet.com/#settings/account as your password

Build on Linux using ```make && sudo make install``` (you'll need libjson-glib-dev, glib-2.0-dev and libpurple-dev packages)

Dll download available from http://eion.robbmob.com/libpushbullet.dll (if you have't downloaded one of my plugins before, download the [json-glib library](https://github.com/EionRobb/pidgin-opensteamworks/raw/master/steam-mobile/libjson-glib-1.0.dll) into your Program Files (x86)\Pidgin folder (or Program Files\Pidgin), NOT into the plugins folder)

# Workaround to setup a working PushBullet Access Token

Unfortunately, the Access Token you create on the Pushbullet website from https://www.pushbullet.com/#settings/account does not allow this plugin to authorize itself properly. The steps below will enable you to workaround this current limitation.

First, make sure you have done a few precautionary steps:

* Enable SMS on Pushbullet on your mobile applicaton
* Login to Pushbullet on your desktop and ensure the desktop app and phone are syncing
* If using a gmail account, ensure your gmail account allows for "less secure" apps to access your account

Second, follow these steps to setup your access token:

 1. Add a Pushbullet account in pidgin with your Pushbullet email address (leave the password option blank)
 2. A prompt window will pop-up with "Approve or Deny" access in Pushbullet. Click "Approve".
 1. A new page will open with the "Success Token" in it. (In Google Chrome) While on the "Success Token" page do the following:
    1. Open the Settings (three buttons to top right) > more tools > developer tools.
    2. In the top columns, select "Application"
    3. On the left hand side, select "Local Storage" > "https:/www.Pushbullet.com/"
    4. In the "Key" column select "Dekstop", to the right in the "Value" Pushbullet access token is " "
    5. Copy this code without the ' ' marks
 4. In Pidgin, Accounts > manage accounts > modify the Pushbullet account
 5. Paste the correct access code, obtained via the steps above, into the password section
