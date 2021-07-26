### vmhook-eac multi-vm

This branch is for EasyAntiCheat drivers which have more than a single virtual machine. Keep in mind that multiple virtual  machines does not mean nested virtualization... 

You can update this code by dumping the rva's of all virtual machine handler tables using [vmprofiler-cli](https://githacks.org/vmp2/vmprofiler-cli/-/commit/3e8df3258ced14c26b8109d77d359482d98bf785). Then you can dump all of the `READQ/DW/W/B` virtual instruction indexes using the `--indexes READ(X)` commandline argument.
