Minimalistic version of TPM driver for Windows 7 and newer.

It contains very basic structures for communication with TPM chip version 1.2 and also implements all authentication principles correctly.

This basic driver can be used as a base for your own embedded driver.

This driver also contains some functions that are not tested at all - e.g. function TakeOwnership was not tested because Windows 7 has TPM ownership, therefore this driver does not have rights to retake ownership.

Other functions are tested well - see the output of test application.
