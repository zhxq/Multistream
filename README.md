# Multistream SSD Tagger
A kernel module to tag stream ID to Linux block I/O requests based on Multi-stream. However, please be aware that Multi-stream is removed from Linux kernel since v5.18.

To compile and install this module as a Linux Kernel module, just run `make`. 

Before loading the kernel module, please check if your SSD supports stream and your OS has enabled stream capability as described in the first two sections of this README. For the usage of the kernel module, see "**Enable the Kernel Module and Assign Processes to Them**" and "**Change Kernel Module Parameters On-the-fly**".

If you are looking for an implementation for AutoStream, see https://github.com/zhxq/AutoStream.

This kernel module is used for the Evaluation section of the paper _Excessive SSD-Internal Parallelism Considered Harmful_ (https://dl.acm.org/doi/abs/10.1145/3599691.3603412). Please consider citing our paper if you use this kernel module in your paper. Thank you!

## Check directory setting
`sudo nvme dir-receive /dev/nvme0n1 -D 1 -O 1 -H`

-D is type and -O is operation. Both = 1 will ask for stream support of this controller (defined in NVMe protocol). -H is to make the result human readable. This can show if the SSD has stream support and maximum number of streams supported by the SSD.


## Enable stream support for Linux Kernel NVMe driver

This is to enable the stream capability in Linux Kernel.

 - Edit /etc/default/grub, add "nvme_core.streams=1" to `GRUB_CMDLINE_LINUX`.
 - Run `sudo update-grub` to update grub settings.
 - Reboot.

## Enable the Kernel Module and Assign Processes to Them

`sudo modprobe streamidtag streams="a;b,c;d,e,f"`

The kernel module accepts a parameter, namely "streams", as a list of processes to be assigned to different streams. To separate streams, use semicolon (;). To separate processes in streams, use comma (,). Trailing semicolons can be skipped (i.e.: ";;d,e,f" is equivalent to ";;d,e,f;").

In this example, it will set parameter `streams` of module `streamidtag` to "a;b,c;d,e,f", which asks the kernel module to assign all write requests by process `a` to stream 2, all write requests by process `b` and `c` to stream 3, and `d`, `e`, `f` to stream 4. Stream 5 has no process assigned. 

You can add **at most 16 streams**. Linux Kernel supports at most four streams, but the Multi-stream feature supports more streams as defined in the NVMe protocol. This kernel module circumvents the limit given by the kernel by setting the `ctrl->nr_streams` to 17. Stream ID in Linux starts from 2, so the **streams ranges from 2 to 17**. FYI, stream 0 is WRITE_LIFE_NOT_SET and stream 1 is WRITE_LIFE_NONE, and they will both be passed as 0 to the SSD - other stream numbers will decrease by 1 (ref: see drivers/nvme/host/core.c).

Similarly, ";;d,e,f;" means assign all write requests by `d`, `e`, `f` to stream 4, and do not assign any write requests by any processes to stream 2, 3, or 5.

## Change Kernel Module Parameters On-the-fly

If you have already loaded the kernel module, but want to change the processes assigned to each write stream, you can use the following command:

`echo "g;h;a,b,c" | sudo tee /sys/module/streamidtag/parameters/streams`

This will set parameter `streams` of module `streamidtag` to "g;h;a,b,c".
