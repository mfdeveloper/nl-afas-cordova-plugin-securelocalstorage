Secure localStorage for Cordova (by Cocoapod)
==========================
This plugin will store local data encrypted using the IOS keychain

WARNING: This is no protection for hackers who have physical/root access to your phone. 
WARNING: If key generation encounters an error (on some rooted android devices), the plugin falls back to NON encrypted localstorage

Use it to store temporary sensitive data which has to survive an app exit/shutdown. 

Requirements
-------------
- iOS 6 or higher

    Installation
-------------
    cordova plugin add nl-afas-cordova-plugin-securelocalstorage

Usage with cordova
------
    
    cordova.plugins.SecureLocalStorage.setItem("key" , "value");

    cordova.plugins.SecureLocalStorage.getItem("key").then(function (value){...})

    cordova.plugins.SecureLocalStorage.removeItem("key");

    cordova.plugins.SecureLocalStorage.clear();




LICENSE
--------
The MIT License (MIT)

Copyright (c) 2015 dickydick1969@hotmail.com Dick Verweij AFAS Software BV - d.verweij@afas.nl


Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
