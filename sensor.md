# Threat modeling of the sensor device

## Overview

This document describes a threat model for a sensor device, running an
application on top of Zephyr.  This device consists of an MCU (such as
an STM32L or NXP K64F type device) connected to an SPI sensor
reporting something such as temperature.  The device reports this data
to a service over the LWM2M protocol over a wireless interface to a
gateway or cloud service.

This first diagram gives a simple overview of this sensor device,
along with how information flows from one part of the system to
another.

- FLASH: The flash memory holds all of the executable code in the
  system, including both the immutable bootloader as well as the two
  apps (or parts of the app).  In addition, this flash will have an
  area set aside to hold keys used for the LWM2M communication with
  the cloud.

- The bootloader lives in FLASH and is responsible for  1. Verifying
  that the App is valid (correctly signed), and 2.  Performing the
  upgrades when requested.  On normal boot, it will begin executing
  the application.

- The main application receives sensor data from the external sensor
  device, and communicates it over the LWM2M protocol to the gateway
  service.  It is also responsible for setting up and maintaining this
  connection with the cloud service.

- The Software Update App receives a new version of the application
  from the cloud, storing it in an extra slot in the FLASH, and when
  ready for update, marks it in such a way that the bootloader knows
  to perform the update.

## Assumptions

This threat model makes the following assumptions:

- The hash functions (SHA256), digital signature algorithms (RSA,
  ECDSA, Ed25519), and symmetric key algorithms (AES256) meet their
  documented security requirements.

## Identified areas of work

In the scope of LITE for this application, the following areas of work
have been identified:

-   Bootloader
    -   Development of signing and provisioning tools suitable to
	protect image signing secrets in a factory environment.
    -   Further analysis and development of alternatives to "image
	swap" currently used for upgrades.
-   Secret storage.  This application requires the storage of several
    device-specific secrets which must be protected from the rest of
    the system.
    -   The only non-volatile memory generally available to these
	devices is the primary FLASH.  Access to this should be
	restricted to as small a portion of the code as possible.
    -   Using the MPU to provide user/kernel separation, although this
	provides some measure of system-wide security, does not
	protect this secret from a majority of the code running on the
	system, especially network and protocol stacks.
    -   The requirement here is to be able to run nearly all of the
	code in non-priveleged mode, and only code needing secrets and
	associated cryptographic operations should run in priveleged
	mode.
    -   This must be designed carefully so that it is not easy for an
	attacker to ask this secure code to perform this operations
	in unintended situations.
-   Protocol analysis
    -   The LWM2M, CoAP, and DTLS protocols have addressed many
	concerns, but all of these have many configure and profile
	choices to make.  Incorrectly configured, they can easily be
	made insecure.
    -   These protocols are large and complex (and some are very new)
	and warrant further analysis of their security.
-   Entropy generation
    -   Although some work has gone into the entropy subsystem in
	Zephyr, more work can be done to make sure this is always
	configured correctly.
    -   The specific hardware entropy sources on member devices should
	be analyzed  Although not usually documented, implementation
	details can be used to determine the quality of the entropy
	source, and adjust parameters, such as how much entropy needs
	to be stirred into a pool to ensure an adequate initial state.

## Threat enumeration

Below is an enumeration of the threats.  Note that this section is
auto-generated from a database of threats.

## THREAT-1: Code run before bootloader

The MCU can be tricked into performing operations before the
bootloader is run.  This can be done through a debug interface,
for example.

### Threat Response

This threat requires access to the hardware. Protecting access
to the components on the device will hinder this attack.
Debug interfaces can be fused out, or not routed to accessible
locations on the board.

### Security Requirement

Deployed hardware shall be configured so that the bootloader is
the first code run. Any debug interfaces that would allow this
boot to be intercepted shall be disabled before deployment.

### Impact

Arbitrary code can be run on the device allowing sensor data
to be spoofed. Can also be used as an attack vector of other
connected devices in the system.

## THREAT-2: Bootloader modification

An attacker could modify the code of the bootloader itself.

### Threat Response

This threat could be done either through a hardware attack
(debugging port), or via software that is able to write to the
flash device.  Preventing debugger access is covered in THREAT-1.

### Security Requirement

Deployed hardware shall be configured such that the bootloader
code is in write protected memory.  This configuration shall be
done through some type of fuse that is irreversible.

### Impact

Arbitrary code can be run on the device.

## THREAT-3: Image verification could be vulnerable

The mechanism that the bootloader uses to validate that the
primary image is valid could be vulnerable.

### Threat Response

The design of robust hashing and signatures is beyond the scope
of this document.  As such, it is important that only algorithms
that are widely understood be used.

### Security Requirement

The bootloader shall use well-known hash and digital signature
algorithms.  Algorithms shall be chosen that are believed to be
resilient for the expected lifetime of the device.

### Impact

The signature could be spoofed, allowing arbitrary code
execution.

## THREAT-4: Root signing key leak

The bootloader signing key could be subverted or leaked. For
example, an attack at the factory could make a clandestine copy
of the private signing key and use it later to sign application
images.

### Threat Response

Although a realistic attack, this is mostly beyond the scope of
this document.  Mainly, it is important that tooling available
provide the necessary functionality for the parties involved to
protect the key.  At a minimum, the key signing should be able to
use some type of key protection hardware.

### Security Requirement

The image signing utilities shall support industry standard key
protection hardware.

### Impact

Arbitrary code execution.

## THREAT-5: Code modification after signing

Once the main application code has started running, the signature
is not rechecked. If the code in flash is changed at this point,
the new code would then execute.

### Threat Response

In order to be able to perform an upgrade, the upgrade app needs
to be able to write to the second slot.  Ideally, it will be
possible to write protect the main slot after the bootloader has
done any updates.

### Security Requirement

Slot 0 (the live image) shall be write protected during normal
operation.

### Impact

Alternative code can be run until the next boot.

## THREAT-6: Insufficient Signature

If there is any part of the image used to control the program
counter that is not included in the signature, this could be
modified out of band, resulting in an undesirable control flow.

### Threat Response

It is important that the signature of the boot image cover every
aspect of the running of this code.  It should cover both code
and initialized data, as well as any data structure, IRQ vector
tables, and other items that are used by the code.

### Impact

Alternate date modifications could cause the application to
execute different behavior.

## THREAT-7: Corrupt application image

The main application image could be corrupted, resulting in an
unbootable system, since the bootloader would refuse to run the
system.

### Threat Response

If an attacker is able to modify the main application image, the
system will be rendered unbootable.  Current MCUboot code assumes
that the image is not modified after it has been written.  It is
also possible for flash to become corrupt over time.

### Security Requirement

None

### Impact

Denial of service.  Non-functioning device.

## THREAT-8: Update to wrong slot

During software update, an update application places the new
image in a secondary slot. It could be tricked into writing
the image to the main image slot instead of the update slot,
bypassing signature checks on the running image.

### Threat Response

Overlap with THREAT-5.  As long as the main image slot is write
protected, the update app should not be able to write to it.

### Security Requirement

None

### Impact

Denial of service.

## THREAT-9: Overfrequent upgrade

The update app could be tricked into writing an image
overly-frequently, prematurely wearing the flash device. It could
also prevent normal functioning of the device because it would be
constantly updating.

### Threat Response

The software update app and protocol needs to be analyzed to
ensure that updates happen neither too infrequently, or too
frequently.

### Security Requirement

An analysis shall be performed of the software update app and
protocol to ensure that updates are performed in a timely manner,
but also are not performed excessively when under attack.

### Impact

Denial of service.

## THREAT-10: Marker prevention

The update app could be prevented from writing the update marker,
which would prevent the update from taking place.

### Threat Response

The update marker is currently written to the same region of
flash as the update slot.  This is mostly mitigated through
review of this code, and general vulnerability prevention.

### Security Requirement

The software update application shall be audited to ensure
correct operation, even under attack.

### Impact

Old code (with possible vulnerabilities) will continue to run.

## THREAT-11: Marker with no upgrade

The app could be tricked into writing the update marker when
there is no upgrade, resulting in a slower startup on subsequent
boot.

### Threat Response

Not a significant impact.

### Security Requirement

None

### Impact

Minimal.  Subsequent reboot is slightly longer.

## THREAT-12: Unnecessary reboots

The update app could be tricked into rebooting unnecessarily,
resulting in denial of service.

### Threat Response

Since the update app needs the ability to reboot, it could be
tricked into rebooting when not needed.

### Security Requirement

Same as THREAT-10

### Impact

Denial of service.

## THREAT-13: Not reboot after upgrade

After an upgrade has been downloaded, the upgrade app must
reboot the device to install the update. If it could be tricked
into delaying this reboot, there is the potential for fixed
vulnerabilities to continue to be runnable.

### Threat Response

Same response as THREAT-10/12.

### Security Requirement

Same as THREAT-10.

### Impact

Old code (with possible vulnerabilities) will continue to run.

## THREAT-14: Corrupt upgrade

If the image in the second slot is corrupt, the bootloader may
take additional time to verify that the signature is invalid.

### Threat Response

Time to verify the second image is similar to the time to verify
the primary image, and the impact is minimal.

### Security Requirement

None

### Impact

Slightly longer startup

## THREAT-15: Bootloader defects

Defects in the bootloader could result in a corrupt main image,
resulting in an unbootable system.

### Threat Response

The image swap implemented in MCUboot is complicated.  A untimely
power loss could provoke defects in this code causing the
main image to be corrupted.  An alternative solution is to not
use swapping, but only image updates, but this makes THREAT-7
more likely, as well as risks updating to an image that is
non-functional, but signed.

### Security Requirement

The bootloader code shall contain a test framework to simulate
untimely resets and power loss.

### Impact

Denial of service

## THREAT-16: Swap code defects

Defects in the image swapping code could allow an untimely power
loss to result in either a corrupt/unbootable image, or the wrong
image in place that hasn't been verified.

### Threat Response

A more specific version of THREAT-15.  The swap code is most
of the complexity in the bootloader. Defects in this code will
result in a system that is unbootable.  It is also possible
that a part could interrupt the swap, modify some of the code
in flash, and the bootloader would then continue to install this
incorrect code, even with an invalid signature.

### Security Requirement

The bootloader shall verify the image signature on every boot,
and not just as part of the upgrade.

### Impact

Arbitrary code execution.

## THREAT-17: Missed upgrade

After an upgrade, the bootloader gives the application a test
boot. If it does not mark itself as good, the bootloader will
roll the image back on the next boot. An untimely powerdown could
force this rollback preventing the upgrade from happening.

### Threat Response

The image upgrade process is fragile, if after the bootloader
finishes the swap, but before the application has marked itself
bad, there is a reboot, the bootloader will consider the image
to have failed, and rollback to the previous version.  Depending
on how the upgrade app is written, this will result in either
the old image running, or the upgrade being repeated, possibly
resulting in a loop.  The tradeoffs here need further analysis.

### Security Requirement

Further analysis.

### Impact

Old code running.  Denial of service preventing booting to normal
system.

## THREAT-18: Upgrade storm

If after a rollback, the system immediately detects that an
upgrade is available, it could result in a device that upgrades
continuously.

### Threat Response

Related to THREAT-17.  If the attacker can prevent boot, the
system will rollback, and then attempt to upgrade again.

### Security Requirement

The upgrade app/service shall have a mechanism to back-off
attempts at upgrade to allow the system to operate, even with an
old version.

### Impact

Denial of service.  Old version running.

## THREAT-19: Anti-rollback

An older image could be sent as an upgrade, causing the
bootloader to downgrade to an older version, possibly reverting
security updates.

### Threat Response

Rollback attacks are a common attack.  Concerns about needing to
revert if bugs are discovered can be addressed by re-labeling the
old version with a new signature.

### Security Requirement

The system shall have a mechanism in place to prevent
installation of an old version of the application.  The mechanism
shall use a hardware feature, such as a monotonically-increasing
non-volatile counter to prevent flash erasure attacks from
defeating it.

### Impact

Installing an old version allows exploitation of already fixed
vulnerabilities.

## THREAT-20: Update server DNS attack

An attacker could subvert DNS, preventing the device from talking
to the upgrade server. This would prevent upgrades from happening
in a timely manner.

### Threat Response

The DNS system should not be considered secure.  It is necessary
for the upgrade system to authenticate the upgraded images.  It
is not necessary to authenticate the upgrade server, only the
communication between the author/signer of the upgrade image and
the upgrade app on the device.

### Security Requirement

The upgrade images shall contain a manifest containing a
description of the target device, version information, and a
digital signature mechanism to verify that the image was created
by a trusted party.

### Impact

Arbitrary code, or prevention of upgrade.

## THREAT-21: Invalid updates on server

An upgrade server could be spoofed, causing invalid images to be
loaded onto the device, and time taken to verify them, as well as
additional reboots.

### Threat Response

Because images will be verified after transferring to the device,
there is low risk of upgrading to an invalid image.  The upgrade
app should verify the image before asking the bootloader to
install it, to prevent a reboot attack.  There is still risk to
consuming excessive bandwidth on the device, as well as possibly
limited power sending invalid images to the device.  There is a
tradeoff between this threat, and requiring trust in the upgrade
server.

### Security Requirement

(tradeoff) The upgrade server shall mutually authenticate with
the device.  The upgrade server shall be audited and monitored
for security vulnerabilities, and patches applied as necessary.

### Impact

Overconsumption of limited network resources will prevent normal
operation of this device, as well as other devices.  Overzealous
updates will result in excessive battery drain, and loss of
operation of the device.

## THREAT-22: Spoofed upgrades

If the upgrade server is spoofed, devices could be tricked into
upgrading to a malicious image.

### Threat Response

Related to THREAT-21.  The authentication of the images should
be sufficient to prevent the target from upgrading to a malicious
image.

### Security Requirement

The upgrade mechanism shall include a small manifest that can be
downloaded separately, and verified to prevent the download of
the full image when there is not an authentic upgrade available.

### Impact

Overconsumption of network resources, and excessive battery
drain.

## THREAT-23: LWM2M susceptible to DNS spoofing

The attacker could spoof a DNS server causing the client to talk
to a host other than the intended server.

### Threat Response

Mutual authentication will mitigate against an incorrect server.
Further analysis should be done on the LWM2M and CoAP protocols.
Concerns specifically are with device provisioning.

### Security Requirement

The client and server of the LWM2M connection shall mutually
authenticate to one another.

### Impact

This can result in either, the sensor data not being delivered
to the correct server, which could result in failure of equipment
(or harm). It could also be used as a step in an in-the-middle
attack, which could deliver malicious sensor data to the
resulting party.

## THREAT-24: LWM2M unencrypted traffic

The attacker could manipulate the LWM2M communication into either
a weak encryption, or using no encryption at all.

### Threat Response

The LWM2M protocol supports non-authenticated connections, which
will result in insecure communication.

### Security Requirement

The protocol stacks shall be configured so that CoAP always uses
DTLS for communication.

### Impact

Observation and spoofing of network traffic.

## THREAT-25: LWM2M system secret leaking

An attacker could retrieve the system secret.

### Threat Response

The system secret needs to be loaded onto the device.  If it can
be read by an attacker, they will be able, at a minimum, to spoof
other devices.  The protocols need to be analyzed further to
understand the extent of this vulnerability.

### Security Requirement

The system secret shall be stored in a protected manner such that
a majority of the code running on the system does not have access
to it.

### Impact

Spoofing of devices.

## THREAT-26: LWM2M observe initial provisioning

An attacker could observe network traffic during LWM2M's
provisioning communication.

### Threat Response

LWM2M supports different provisioning procedures, such as
pre-shared secrets, raw public keys, and certificates.  The
device must have credentials for the bootstrap server.  Depending
on the protocols used, an attacker observing initial provisioning
can learn the device credentials and use this to observer later
traffic.

### Security Requirement

LWM2M/CoAP shall be provisioned to use a provisioning procedure
that is not susceptible to revealing credentials during
observation.  The stacks shall be configured to use cipher suites
that provide perfect forward secrecy (PFS).

### Impact

Traffic can be visible to the attacker.  Traffic can be spoofed
by the attacker.

## THREAT-27: LWM2M force re-provisioning

An attacker could disrupt communication in a way that would
result in the device re-provisioning itself.

### Threat Response

The LWM2M protocol will re-provision itself if it is not able to
communicate with the server.  If the attacker is able to spoof
both the server and the bootstrap server, the device would then
be vulnerable to a party-in-the-middle attack by the attacker.
 Some of this is addressed by keeping the bootstrap credentials
protected.

### Security Requirement

The LWM2M protocol shall be analyzed for the security tradeoffs
over automatic re-provisioning and attacks against this.

### Impact

Interception and spoofing of communication.

## THREAT-28: LWM2M device identity tampering

An attacker could manipulate the device's notion of identity.
Many MCU's do not have unique serial numbers, and the attacker
could manipulate a MAC or other per-device value.

### Threat Response

Related to THREAT-27.  If the identity of the device can be
changed, the device could be spoofed, or cause false sensor data
to be returned.

### Security Requirement

The device shall have a unique, immutable, identity that is
associated with the device-specific credentials.

### Impact

Spoofing of device.

## THREAT-29: LWM2M weak random

An attacker could manipulate the entropy source used to generate
IVs and/or session keys.

### Threat Response

Without a sufficient entropy source, some parameters used for
security protocols become vulnerable.  In general, devices
should have an adequate hardware entropy source.  The entropy
source shall not be accessible to an outside observer, as this
information reduces attack space.

### Security Requirement

The system shall be configured to use either 1. An on-chip
hardware entropy source, or 2. A suitable device-specific CPRNG
with state that is stored on the device that is a. Inaccessible
to outside observers, b. updated each time the state changes, c.
read on power up, d. initialized using a good entropy source.

### Impact

Reduced security of cryptographic protocols.

## THREAT-30: SPI interception

The external sensor uses an SPI bus over external wires. An
attacker could intercept this signal, and either read or spoof
sensor data.

### Threat Response

This requires physical access to the device.  It can be mitigated
by making these signals less accessible.

### Security Requirement

The hardware shall be designed to make interception of the SPI
bus difficult.

### Impact

Spoofed sensor data.

## THREAT-31: Sensor manipulation

The external sensor can be attacked by placing, say a hot or cold
(or humid) source next to the sensor.

### Threat Response

This threat can be considered beyond the scope of this document.

### Security Requirement

None

### Impact

Spoofed sensor data.

