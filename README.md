# sshRunCMD

Use this software to ssh into multiple network switches at the same time to update configs. At this time (Nov 2023) SolarWinds does not support Transition Network switches which is the birth of this application. Past that we have full support for newer and older Cisco switches and are happy to add broader support for other devices if you find this doesn't work, just submit a new feature above. 

The helper file contains the encrypted local admin credentials and you can add your own credentials to the primary spot since most of our devices are managed through AD. If not you need to add your credentials on each run inside the application under File. 

![image](https://github.com/Rldeckard/sshRunCMD/assets/30917551/146c54f6-3b89-4521-aca1-899e6da13904)


## Getting Started


### Installing Fyne

If you try to run the application using `go run . ` right out of the gate you'll get the below error because Fyne isn't installed. You can verify this using the command `gcc`. If you receive the below error for either your build is not ready.

```

imports github.com/go-gl/gl/v2.1/gl: build constraints exclude all Go files in \go\pkg\mod\github.com\go-gl\gl@v0.0.0-20231021071112-07e5d0ea2e71\v2.1\gl

PS C:\Users\user\Documents\GitHub\sshRunCMD> gcc
gcc : The term 'gcc' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify 
that the path is correct and try again.
At line:1 char:1
+ gcc
+ ~~~
    + CategoryInfo          : ObjectNotFound: (gcc:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

```

Follow the installing Fyne getting started guide to get the proper C compiler https://docs.fyne.io/started/quick/. Compling in C with Fyne is expected to take quite a bit longer so be prepared for that.

Waiting several minutes on the first run

Run `go mod tidy` once everything is installed to sync up your install with the freshly installed files

### Packaging Desktop Application Release

`fyne build .`
