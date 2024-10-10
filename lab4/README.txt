1. Identify what aspects of the work have been correctly implemented and what have not.
To my knowledge, everything has been implemented correctly. I used a shell script to test each use case.

2. Identify anyone with whom you have collaborated or discussed the assignment.
I did this lab by myself.

3. Say approximately how many hours you have spent completing the assignment.
3 hours

4. Be written in either text format. No other formats will be accepted.
Check

5. List any additional dependencies used.
No additional dependencies.
I only used scapy and argparse, which came with the starter code. I also used the
base64 library, which was approved per a piazza post.

For this lab, you must also address the following questions:
6. Are the heuristics used in this assignment to determine incidents "even that good"?
The heuristics used in this assignment are helpful for detecting simple incidents,
and are helpful to consider for avoiding simple vulnerabilities. However, the
usefulness of these heuristics is limited because a real attacker would probably
be able to avoid detection by the alarm program. For instance, they could attack
the system on a non-monitored port number, and escape detection by the alarm.

7. If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?
It might be useful to track the state of TCP connections. If we were experiencing
an attack from many different IP addresses clustered in one region, and were able to
see that they were initiating contact with a SYN, but not acknowledging the SYN-ACK
with an ACK, that a potential DDOS attack was being launched. Maybe this is a
little far fetched for the scope of this lab, but nevertheless the state of TCP
connections is not tracked by the current program.

Justifying the use of ChatGPT:

What I used it for:
ChatGPT was helpful for resolving a bug. When trying to detect credentials,
decoding to ascii would return gobbledy gook in some cases. Decoding to utf-8 was
more effective at avoiding printing binary.

I also asked it to help me decode the base64 passwords I was getting as alerts.
It generated a useful helper function for me.

Prompts I asked it:
1. "Does it matter if I decode with utf 8 or ascii?"

2. "Here are the results from scanning a pcap for credentials:

ALERT #7: Credentials sent in cleartext with HTTP is detected from 192.168.1.242 (HTTP) (GET /admin/ HTTP/1.1
Host: 192.168.1.219
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Authorization: Basic dG9tYnJhZHk6VEIxMklzVGhlR09BVA==

)!
ALERT #8: Credentials sent in cleartext with HTTP is detected from 192.168.1.242 (HTTP) (GET /admin/ HTTP/1.1
Host: 192.168.1.219
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Authorization: Basic YmJveDpSb2Nrc3RlYWR5

It seems like the credentials are represented in base 64. How can I convert the credentials to utf 8?"
