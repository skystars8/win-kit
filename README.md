







<img width="337" height="248" alt="c" src="https://github.com/user-attachments/assets/5de4eccf-36e6-4ca9-a652-0237e28ac673" />

# Simplicity by design 

With the ultimate power couple of Rust lang and Ai, anyone can vibe code awesome apps. It is just silly to rely on some random app that you download from the internet unless you can see the code. This repo is a bunch of simple Rust apps for windows. Extremely easy to audit, just feed the tiny file to ai in order for it to change anything for you.



Note- 

SmartScreen is mostly triggered by the **Mark of the Web** (MotW). When a file is downloaded from the internet (or comes from email/USB in some cases), Windows stamps it with a Zone.Identifier alternate data stream. That flag is what makes SmartScreen check reputation and often show the blue “Windows protected your PC” screen.

When you compile with `cargo build` (or `cargo run`) on your own machine:

- The `.exe` is created locally
- It has **no** Mark of the Web
- SmartScreen usually stays quiet

That’s why you didn’t see the warning.

If you copy that same `.exe` to another computer, upload it somewhere and download it again, or email it to yourself, then SmartScreen will almost certainly start complaining until the binary builds some reputation.

So local development/build is the easy path — the friction only really appears once the file leaves your machine.

