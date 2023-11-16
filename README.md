# sshRunCMD

Use this software to ssh into multiple transition network switches at the same time to update configs. Sometimes when the network scan finishes you'll notice mass changes that need to be made or you'll need to add a new Radius server. At this time (Nov 2023) we're unable to manage the transition network switches using Solarwinds so this works for now. 

The helper file contains the encrypted local admin credentials and you can add your own credentials to the primary spot since most of our devices are managed through AD. If not you need to add your credentials on each run inside the application under File. 