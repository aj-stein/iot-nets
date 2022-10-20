---
title: A summary of security-enabling technologies for IoT devices
abbrev: IoT networking security guidelines
docname: draft-moran-iot-nets-01
category: info

ipr: trust200902
area: Security
workgroup: IOTOPS
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
  docmapping: yes
  toc_levels: 4

author:
 -
      ins: B. Moran
      name: Brendan Moran
      organization: Arm Limited
      email: Brendan.Moran@arm.com


normative:
  RFC8520:
  RFC8995:
  RFC7030:
  FDO:
    title: "FIDO Device Onboarding"
    author:
    -
      ins: "FIDO Alliance"
    target: https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.0-20201202.html
  LwM2M:
    title: "LwM2M Core Specification"
    author:
    target: http://openmobilealliance.org/release/LightweightM2M/V1_2-20201110-A/OMA-TS-LightweightM2M_Core-V1_2-20201110-A.pdf
  SWID:
    title: "Software Identification (SWID) Tagging"
    author:
    -
      ins: "NIST"
    target: https://csrc.nist.gov/Projects/Software-Identification-SWID/guidelines
  I-D.ietf-rats-eat:
  I-D.ietf-suit-manifest:
  I-D.ietf-sacm-coswid:
  I-D.birkholz-rats-corim:
  I-D.ietf-teep-architecture:
  I-D.ietf-rats-architecture:

  IoTopia:
    title: "Global Platform Iotopia"
    target: https://globalplatform.org/iotopia/mud-file-service/

--- abstract

The IETF has developed security technologies that help to secure the Internet of Things even over constrained networks and when targetting constrained nodes. These technologies can be used independenly or can be composed into larger systems to mitigate a variety of threats. This documents illustrates an overview over these technologies and highlights their relationships. Ultimately, a threat model is presented as a basis to derive requirements that interconnect existing and emerging solution technologies.

--- middle

# Introduction

This memo serves as an entry-point to detail which technologies are available for use in IoT networks and to enable IoT designers to discover technologies that may solve their problems. This draft addresses.

This draft addresses six trustworthiness problems in IoT devices; expressed simply as six questions:

1.  What software is my device running?
2.  How should my device connect to a network?
3.  With which systems should my device communicate?
4.  What is the provenance of my device's software and corresponding policies?
5.  Who is authorised to initiate a software update and under which conditions?
6.  How should my device trust updates to its software?

Each of these questions is answered by recently developed or developing standards. Each of these questions hides a security threat; so these threats are detailed in a threat model.

# Threats and Risks to IoT Deployments

For this threat model to be useful to implementers, there are certain usability requirements that must be included to explain the origin of a threat. These are noted where necessary.

Sections are organised in groups of: 

- usability requirement (if needed)
- threat
- security requirement
- mitigating technologies

## Threat: IoT Network Credential Exposure

Network Credential Exposure describes the potential for exposure of credentials, including cryptographic material, used to access an IoT network. Note that "network" here describes a logical network, such as a LwM2M server and its clients.

Each physical network technology provides its own onboarding techniques. Recommended practice is to follow best practices for the physical network technology in use.


### REQ.USE.NET.CREDENTIALS

It must be possible to provide a device with credentials to access a network. This is typically referred to as device onboarding. This may be done by the manufacturer, the supply chain, the installer, or the end user. It may be done by the device or on behalf of the device by a trusted third party.

### THREAT.IOT.NET.CREDENTIALS

A threat actor extracts the credentials from a device or by eavesdropping on the credential provisioning flow

### REQ.SEC.NET.CREDENTIALS

Network access credentials must be provisioned to a device in a way that secures them against eavesdropping or extraction.

### Technologies to Mitigate THREAT.IOT.NET.CREDENTIALS

Several technologies are available for device onboarding:

- Lightweight M2M Bootstrap {{LwM2M}} provides a mechanism to provision keying material and configuration of any kind, according to a well-defined data model.
- FIDO Device Onboard {{FDO}} provides a mechanism to deliver an arbitrary block of data to devices. This block of data can contain trust anchors, cryptographic information, and other device configuration. 
- BRSKI {{RFC8995}} provides a mechanism for "Bootstrap Distribution of CA Certificates", as described in [RFC7030], Section 4.1.1.  In the process, a TLS connection is established that can be directly used for Enrollment over Secure Transport (EST).
- Enrollment over Secure Transport (EST) {{RFC7030}} provides a mechanism to deliver certificates and, optionally, private keys to devices.

## Threat: Trust Anchor Private Key Disclosure

When a trust anchor of a device is used regularly, the chances of its private key being disclosed increase.

### THREAT.IOT.TA.DISCLOSURE

A private key trusted by one or more devices is disclosed. This could be caused by: a threat actor within the organisation, a compromise of a service using the key, etc.

### REQ.SEC.TA.ROTATION

It must be possible to deploy new keys to devices in order to update their active trust anchors. This does not mean that the ultimate trust anchor over a device is changed, but that its delegates are changed, enabling infrequent use of the ultimate trust anchor and higher security key management protocols to be deployed, such as key ceremonies and M of N threshold signatures.

### Technologies to mitigate THREAT.IOT.TA.DISCLOSURE

Several technologies are available for trust anchor rotation:

- Lightweight M2M Bootstrap {{LwM2M}} provides a mechanism to provision keying material and configuration of any kind, according to a well-defined data model.
- FIDO Device Onboard {{FDO}} provides a mechanism to deliver an arbitrary block of data to devices. This block of data can contain trust anchors, cryptographic information, and other device configuration. 
- Enrollment over Secure Transport (EST) {{RFC7030}} provides a mechanism to deliver certificates and, optionally, private keys to devices.

## Threat: Incorrect Firmware/Version

Incorrect firmware/version can come in two forms.

### THREAT.FW.OLD

Old firmware present on device allows compromise of data sent to device, poisoning of data sent to service

### THREAT.DEV.ROGUE

Rogue or simulated device emulates a real device, allows compromise of data sent to the device, or poisoning of data sent to service

### REQ.SEC.FW.MEASURE

To enable devices to report their current software version and related data securely, devices SHOULD support a support a mechanism to securely measure their firmware. This allows an IoT network to restrict access by non-compliant devices.

### Technologies to implement REQ.SEC.FW.MEASURE

The technology used for securely measuring and reporting the firmware of a device is typically called remote attestation. A protocol is under development for conveying remote attestation measurements in a trustworthy way in {{I-D.ietf-rats-architecture}}. Likewise, document format is under development in {{I-D.ietf-rats-eat}}.

## Threat: Vulnerable Firmware

Devices with old firmware might have a known vulnerability. This could allow a threat actor to take over the device.

### THREAT.FW.KNOWN.VULNERABILITY

If old firmware with known vulnerability cannot be altered. This allows exploit of known a vulnerability.

### REQ.SEC.FW.REMOTE.UPDATE

Software on unattended devices must be remotely-updatable.

### THREAT.UPDATE.COMPROMISE

Compromise of the update system is fundamentally equivalent to persistent remote code execution. A threat actor that gains firmware update capability has extensive power over the device.

### REQ.SEC.UPDATE.SECURITY

Software update mechanism must be secured (see RFC9124)

### Technologies to implement REQ.SEC.UPDATE.SECURITY

To enable devices to be updated securely in the field, they can support a remote update protocol such as {{I-D.ietf-suit-manifest}}. For securely deploying software to Trusted Execution Environments, the a secure Trusted Application delivery protocol should be used, such as {{I-D.ietf-teep-architecture}}.

## Threat: Supply Chain Attacks

Software of unknown origin may be used in a device. If an threat actor can gain control over the software supply chain, they may be able to sneak their code onto a device.

### RISK.SW.SUPPLY

Software of unknown origin may be used in a device

### THREAT.SW.SUPPLY

If software origin is not verified, a threat actor may deliberately and secretly seed the software supply chain with vulnerable code, enabling further compromise.

### REQ.SEC.SW.BOM

To prove the provenance of a firmware update, update manifests SHOULD include (directly, or by secure reference) a Software Identifier or Software Bill of Materials,

### Technologies to implement REQ.SEC.UPDATE.SECURITY

In order to enable a device to prove provenance of its software, it or its network can use a software identifier such as {{I-D.ietf-sacm-coswid}}. Optionally, this software idenifier can be encapsulated in a manifest that includes hardware properties as well, such as {{I-D.birkholz-rats-corim}}.

## Risk: Verification Information Supply Chain

Correct values for attestation results may not be known by Verifiers, causing them to log values, but not limit them.

### RISK.VERIFIER.DEFAULTS

Without access to a source of verification information such as expected attestation results, a verifier may not be able to make correct decisions about the trustworthiness of a device.

### THREAT.TRUST.ELEVATION

A threat actor deploys compromised software to devices; this is detected by monitoring systems, but not identified as an attack. If a threat actor can cause an attestation system to trust a device more than it should, this forms a new class of elevation of privilege: elevation of trust.

### REQ.SEC.VERIFIER.DATA

Monitoring systems must know the expected values in Attestation results.

### Technologies to implement REQ.SEC.VERIFIER.DATA

To enable a Relying Party of the Remote Attestation to correctly evaluate the Attestation Report, the SBoM (such as {{I-D.ietf-sacm-coswid}}) can contain expected values for the Attestation Report. In addition, the expected information for hardware properties can be contained in another manifest, such as {{I-D.birkholz-rats-corim}}.

NOTE: Remote attestation terminology is fluid on this topic. A "Verifier" can be any system that appraises Evidence in remote attestation. It is expected that "appraisal" will be spread across at least two systems to maintain confidentiality and separation of responsibility: 1) a Verifier that ensures that the attestation Evidence is produced by genuine hardware, not tampered with, and not signed by revoked keys and 2) a monitoring system taking on the role of Verifier and Relying Party that appraises whether a device has the correct software versions and initiates remediation if not.

## Threat: Spurious Network Capabilites

Devices may have additional, unneeded capabilites that are detrimental to network security. While the best option is to disable this functionality in software, this is not always practical

### THREAT.NET.SPURIOUS.FUNCTIONS

Devices may contain intentional or accidental capabilities to make networks vulnerable or launch attacks on other networks. These capabilities are extremely costly to discover by inspection or audit.
Requirement: Devices (or their supply chains) must advertise their network access requirements and networks must enforce that devices adhere to their stated network access requirements.

### REQ.SEC.NET.ACL

To ensure that network infrastructure is configured discern the difference between authentic traffic and anomalous traffic, network infrastructure can implement fine-grained access control over how a device can use a network

### THREAT.NET.BAD.ACL

If a service hosting network access requirements documents is compromised, it can be used to enable malicious devices to mount attacks.

### REQ.SEC.NET.ACL.SIGNATURE

Network access ACL documents should be signed. Best practice is to use offline keys for signing.

### THREAT.NET.WRONG.ACL

If devices are permitted to self-report ACLs without authentication by a trusted party, they can report any ACL recognised by the network. A device can mis-advertise its network access requirements, pretending to be a different, but recognised and more privileged device (potentially cloning MAC addresses, keys, etc.)

### REQ.SEC.NET.ACL.TRUST

Network Access Requirements documents must be secured against tampering and misreporting

### RISK.NET.ACL.CONFLATION

Network Access Requirements documents embedded in or referenced from device certificates conflate two capabilities for network operators: network access requirement authorship (potentially delegated) and network access requirement audit. While network operators should audit network access requirements, authoring those requirements should be done by the authors of the device behavior.

Failure to separate these capabilities has the potential to lead to failed device behaviour due to wrong Network Access Requirements descriptions, leading to disabling of the network ACL system in the name of expediency.

### REQ.SEC.NET.ACL.SEPARATION

Requirement: If Network Access Requirements are embedded in or referenced by device certificates, the responsibility for network access requirement authorship should be delegated to the device application authors. Alternatively, this can be done explicitly by tying device application authorship to device network access requirements authorship.

### Technologies to Mitigate Spurious Network Capabilities

1. THREAT.NET.SPURIOUS.FUNCTIONS can be mitigated by use of {{RFC8520}} Manufacturer Usage Descriptions (MUDs) and a MUD Controller which accepts MUD files in order to automatically program rules into the network infrastructure.
2. THREAT.NET.BAD.ACL To prevent a threat actor from distributing their own MUD files via a MUD server, these can be signed, preferably with an offline key as described in {{RFC8520}}.
3. THREAT.NET.WRONG.ACL can be mitigated by using 802.1X, or SUIT to contain a MUD file or MUD file reference and integrity check. Alternatively, the device's RATS attestation results can be compared to a known list of device profiles and a MUD can be applied as a result without intervention from the remote device.
4. REQ.SEC.NET.ACL.SEPARATION can be mitigated either through key delegation or through the use of SUIT encapsulation of the MUD file. A third option is to use a third-party ACL provider, such as iotopia.

## Risk: DoS of ACL server

### RISK.NET.ACL.UPDATE

Recently updated devices may incur latency penalties when a new network access requirements reference must be resolved and verified.

### THREAT.NET.ACL.DOS

A threat actor may block access to a distributor of network access requirements documents, thus disabling all devices referencing the network access requirements documents it hosts, without any network intrusion necessary against target networks.

### REQ.SEC.NET.ACL.LOCAL

Network access requirements documents should be distributed in advance of use by any device because they constitute a non-local software dependency

### Technologies to Implement REQ.SEC.NET.ACL.LOCAL

In order for network infrastructure to be configured in advance of any changes to devices, MUD files can be transported (directly or by secure reference) within update manifests.

This allows local infrastructure to delay installation of a firmware update until a new MUD file can be fetched and audited.

## Threat: Delays in ACL Remediation

If an ACL is wrong, network operators need it to be fixed quickly.

### THREAT.NET.ACL.BROAD

A network access requirements document grants permissions to a device that are too broad, but the provider of firmware updates is slow to respond, meaning that MUD file delivery in SUIT will take too long.

### REQ.SEC.NET.ACL.DYNAMIC

It must be possible to distribute reduced permissions to network access controllers to mitigate a wrong ACL. To enable rapid response to evolving threats, the MUD controller SHOULD also support dynamic update of MUD files. 

### Technologies that implement REQ.SEC.NET.ACL.DYNAMIC

If a MUD file is delivered by SUIT rather than via a remote server, then a secondary delivery channel can be used. This can include manually overriding the ACL in the network infrastructure. It can also include using SUIT to deliver the key that is used to verify signed MUD files from a specific URL, however in this scenario, THREAT.NET.ACL.DOS remains unmitigated.

## Threat: Vulnerable Devices

If a vulnerable device is connected to the network, it could be a risk to the whole network.

### THREAT.NET.VULNERABLE.DEVICE

Old firmware with known vulnerability allows exploit until it is updated.

### REQ.SEC.NET.DMZ

Network infrastructure can apply risk management policy to devices that attest non-compliant configuration. For example, a device with out-of-date firmware may only be permitted to access the update system.

### Technologies to Implement REQ.SEC.NET.DMZ

Using MUD and RATS, a network operator can force a device onto a DMZ network containing only attestation and SUIT update services until it successfully attests a correct firmware version.

--- back

