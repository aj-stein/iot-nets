---
title: A summary of security-enabling technologies for IoT devices
abbrev: IoT networking security summary
docname: draft-ietf-iotops-security-summary-01
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
      email: brendan.moran.ietf@gmail.com


normative:
  RFC4122:
  RFC8520:
  RFC8995:
  RFC7030:
  RFC8446:
  RFC9019:
  RFC9203:
  RFC8152:
  RFC9000:
  RFC9124:
  RFC9147:
  RFC9397:
  FDO:
    title: "FIDO Device Onboarding"
    author:
    -
      ins: "FIDO Alliance"
    target: https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.0-20201202.html
  LwM2M:
    title: "LwM2M Core Specification"
    target: http://openmobilealliance.org/release/LightweightM2M/V1_2-20201110-A/OMA-TS-LightweightM2M_Core-V1_2-20201110-A.pdf
    author:
    -
      ins: "OMA"
  ENISA-Baseline:
    title: "Baseline Security Recommendations for IoT in the context of Critical Information Infrastructures"
    author:
    -
      ins: "ENISA"
    target: https://www.enisa.europa.eu/publications/baseline-security-recommendations-for-iot/
  ETSI-Baseline:
    title: "Cyber Security for Consumer Internet of Things: Baseline Requirements"
    author:
    -
      ins: "ETSI"
    target: https://www.etsi.org/deliver/etsi_en/303600_303699/303645/02.01.01_60/en_303645v020101p.pdf
  NIST-Baseline:
    title: "IoT Device Cybersecurity Capability Core Baseline"
    author:
    -
      ins: "NIST"
    target: https://www.nist.gov/publications/iot-device-cybersecurity-capability-core-baseline


  I-D.ietf-rats-eat:
  I-D.ietf-suit-manifest:
  I-D.ietf-sacm-coswid:
  I-D.birkholz-rats-corim:
  I-D.ietf-teep-architecture:
  I-D.ietf-teep-protocol:
  I-D.ietf-rats-architecture:
  I-D.ietf-suit-report:
  I-D.fossati-tls-attestation:
  I-D.ietf-scitt-architecture:


  IoTopia:
    title: "Global Platform Iotopia"
    target: https://globalplatform.org/iotopia/mud-file-service/

--- abstract

The IETF has developed security technologies that help to secure the Internet of Things even over constrained networks and when targetting constrained nodes. These technologies can be used independenly or can be composed into larger systems to mitigate a variety of threats. This documents illustrates an overview over these technologies and highlights their relationships. Ultimately, a threat model is presented as a basis to derive requirements that interconnect existing and emerging solution technologies.

--- middle
# Introduction

This memo serves as an entry-point to detail which technologies are available for use in IoT networks and to enable IoT designers to discover technologies that may solve their problems. This draft addresses.

Many baseline security requirements documents have been drafted by standards setting organisations, however these documents typically do not specify the technologies available to satisfy those requirements. They also do not express the next steps if an implementor wants to go above and beyond the baseline in order to differentiate their products and enable even better security. This memo defines the mapping from some IoT baseline security requirements definitions to ietf and related security technologies. It also highlights some gaps in those IoT baseline security requirements.

#  Conventions and Terminology

{::boilerplate bcp14}

# Survey of baseline security requirements 

At time of writing, there are IoT baseline security requirements provided by several organisations:

* ENISA's Baseline Security Recommendations for IoT in the context of Critical Information Infrastructures ({{ENISA-Baseline}})
* ETSI's Cyber Security for Consumer Internet of Things: Baseline Requirements {{ETSI-Baseline}}
* NIST's IoT Device Cybersecurity Capability Core Baseline {{NIST-Baseline}}

# Requirement Mapping

Requirements that pertain to hardware, procedure, and policy compliance are noted, but do not map to ietf and related technologies. NIST's requirements ({{NIST-Baseline}}) are very broad and already have mappings to ENISA baseline security recommendations.

## Hardware Security

### Identity

ENISA GP-PS-10: Establish and maintain asset management procedures and configuration controls for key network and information systems.

NIST Device Identification: The IoT device can be uniquely identified logically and physically.

ETSI Provision 5.4-2: Where a hard-coded unique per device identity is used in a device for security purposes, it shall be implemented in such a way that it resists tampering by means such as physical, electrical or software.

These requirements are architectural requirements, however {{RFC4122}} can be used for identifiers.

### Hardware Immutable Root of Trust

ENISA GP-TM-01: Employ a hardware-based immutable root of trust.

This is an architectural requirement.

### Hardware-Backed Secret Storage

ENISA GP-TM-02: Use hardware that incorporates security features to strengthen the protection and integrity of the device - for example, specialized security chips / coprocessors that integrate security at the transistor level, embedded in the processor, providing, among other things, a trusted storage of device identity and authentication means, protection of keys at rest and in use, and preventing unprivileged from accessing to security sensitive code. Protection against local and physical attacks can be covered via functional security.

NIST Data Protection: The ability to use demonstrably secure cryptographic modules for standardized cryptographic algorithms (e.g., encryption with authentication, cryptographic hashes, digital signature validation) to prevent the confidentiality and integrity of the device’s stored and transmitted data from being compromised

ETSI Provision 5.4-1: Sensitive security parameters in persistent storage shall be stored securely by the device.

This is an architectural requirement.

## Software Integrity & Authenticity

### Boot Environment Trustworthiness and Integrity

ENISA GP-TM-03: Trust must be established in the boot environment before any trust in any other software or executable program can be claimed.

ETSI defines the following boot environment requirements:

* Provision 5.7-1: The consumer IoT device should verify its software using secure boot mechanisms.


Satisfying this requirement can be done in several ways, increasing in security guarantees:

1. Implement secure boot to verify the bootloader and boot environment. Trust is established purely by construction: if code is running in the boot environment, it must have been signed, therefore it is trustworthy.
2. Record critical measurements of each step of boot in a TPM. Trust is established by evaluating the measurements recorded by the TPM.
3. Use Remote Attestation. Remote attestation allows a device to report to third parties the critical measurements it has recorded (either in a TPM or signed by each stage) in order to prove the trustworthiness of the boot environment and running software. Remote Attestation is implemented in {{I-D.ietf-rats-eat}}.

### Code Integrity and Authenticity

ENISA GP-TM-04: Sign code cryptographically to ensure it has not been tampered with after signing it as safe for the device, and implement run-time protection and secure execution monitoring to make sure malicious attacks do not overwrite code after it is loaded.

Satisfying this requirement requires a secure invocation mechanism. In monolithic IoT software images, this is accomplished by Secure Boot. In IoT devices with more fully-featured operating systems, this is accomplished with an operating system-specific code signing practice.

Secure Invocation can be achieved using the SUIT Manifest format, which provides for secure invocation procedures. See {{I-D.ietf-suit-manifest}}.

To satisfy the associated requirement of run-time protection and secure execution monitoring, the use of a TEE is recommended to protect sensitive processes. The TEEP protocol (see {{I-D.ietf-teep-architecture}}) is recommended for managing TEEs.

### Secure Software/Firmware Update

Technical requirements for Software Updates are provided for in the SUIT information model ({{RFC9124}}) and TEEP Architecture ({{RFC9397}}). Procedural and architectural requirements should be independently assessed by the implementor.

ENISA Software Update Requirements:

* GP-TM-05: Control the installation of software in operating systems, to prevent unauthenticated software and files from being loaded onto it.
* GP-TM-18: Ensure that the device software/firmware, its configuration and its applications have the ability to update Over-The-Air (OTA), that the update server is secure, that the update file is transmitted via a secure connection, that it does not contain sensitive data (e.g. hardcoded credentials), that it is signed by an authorised trust entity and encrypted using accepted encryption methods, and that the update package has its digital signature, signing certificate and signing certificate chain, verified by the device before the update process begins.
* GP-TM-19: Offer an automatic firmware update mechanism.
* GP-TM-20: (Procedural / Architectural) Backward compatibility of firmware updates. Automatic firmware updates should not modify user-configured preferences, security, and/or privacy settings without user notification. 

NIST Software Update:

1. The ability to update the device’s software through remote (e.g., network download) and/or local means (e.g., removable media)
2. The ability to verify and authenticate any update before installing it
3. The ability for authorized entities to roll back updated software to a previous version
4. The ability to restrict updating actions to authorized entities only
5. The ability to enable or disable updating
6. Configuration settings for use with the Device Configuration capability including, but not limited to:

  1. The ability to configure any remote update mechanisms to be either automatically or manually initiated for update downloads and installations
  2. The ability to enable or disable notification when an update is available and specify who or what is to be notified

ETSI Keep Software Updated:

* Provision 5.3-1 All software components in consumer IoT devices should be securely updateable.
* Provision 5.3-2 When the device is not a constrained device, it shall have an update mechanism for the secure installation of updates.
* Provision 5.3-3 An update shall be simple for the user to apply.
* Provision 5.3-4 Automatic mechanisms should be used for software updates.
* Provision 5.3-5 The device should check after initialization, and then periodically, whether security updates are available.
* Provision 5.3-6 If the device supports automatic updates and/or update notifications, these should be enabled in the initialized state and configurable so that the user can enable, disable, or postpone installation of security updates and/or update notifications.
* Provision 5.3-7 The device shall use best practice cryptography to facilitate secure update mechanisms.
* Provision 5.3-8 Security updates shall be timely.
* Provision 5.3-9 The device should verify the authenticity and integrity of software updates.
* Provision 5.3-10 Where updates are delivered over a network interface, the device shall verify the authenticity and integrity of each update via a trust relationship.
* Provision 5.3-11 The manufacturer should inform the user in a recognizable and apparent manner that a security update is required together with information on the risks mitigated by that update.
* Provision 5.3-12 The device should notify the user when the application of a software update will disrupt the basic functioning of the device.
* Provision 5.3-13 The manufacturer shall publish, in an accessible way that is clear and transparent to the user, the defined support period.
* Provision 5.3-14 For constrained devices that cannot have their software updated, the rationale for the absence of software updates, the period and method of hardware replacement support and a defined support period should be published by the manufacturer in an accessible way that is clear and transparent to the user.
* Provision 5.3-15 For constrained devices that cannot have their software updated, the product should be isolable and the hardware replaceable.
* Provision 5.3-16 The model designation of the consumer IoT device shall be clearly recognizable, either by labelling on the device or via a physical interface.
* Provision 5.5-3 Cryptographic algorithms and primitives should be updateable.

Many fully-featured operating systems have dedicated means of implementing this requirement. The SUIT manifest (See {{I-D.ietf-suit-manifest}}) is recommended as a means of providing secure, authenticated software update, including for constrained devices. Where the software is deployed to a TEE, TEEP (See {{I-D.ietf-teep-protocol}}) is recommended for software update and management.

### Configuration

NIST Device Configuration:

1. The ability to change the device’s software configuration settings
2. The ability to restrict configuration changes to authorized entities only
3. The ability for authorized entities to restore the device to a secure configuration defined by an authorized entity

ETSI defines the following configuration requirements:

* Provision 5.12-1: Installation and maintenance of consumer IoT should involve minimal decisions by the user and should follow security best practice on usability.
* Provision 5.12-2 The manufacturer should provide users with guidance on how to securely set up their device.
* Provision 5.12-3 The manufacturer should provide users with guidance on how to check whether their device is securely set up.

Configuration can be delivered to a device either via a firmware update, such as in {{I-D.ietf-suit-manifest}}, or via a runtime configuration interface, such as {{LwM2M}}.

### Resilience to Failure

ENISA GP-TM-06: Enable a system to return to a state that was known to be secure, after a security breach has occured or if an upgrade has not been successful.

ETSI defines the following resilience requirements:

* Provision 5.9-1: Resilience should be built in to consumer IoT devices and services, taking into account the possibility of outages of data networks and power.
* Provision 5.9-2: Consumer IoT devices should remain operating and locally functional in the case of a loss of network access and should recover cleanly in the case of restoration of a loss of power.
* Provision 5.9-3: The consumer IoT device should connect to networks in an expected, operational and stable state and in an orderly fashion, taking the capability of the infrastructure into consideration.

While there is no specificaiton for this, it is also required in {{RFC9019}}

### Trust Anchor Management

ENISA GP-TM-07: Use protocols and mechanisms able to represent and manage trust and trust relationships.

EST ({{https://datatracker.ietf.org/doc/html/rfc7030}}) and LwM2M Bootstrap ({{LwM2M}}) provide a mechanism to replace trust anchors (manage trust/trust relationships).

## Default Security & Privacy

### Security ON by Default

ENISA GP-TM-08: Any applicable security features should be enabled by default, and any unused or insecure functionalities should be disabled by default.

NIST Logical Access to Interfaces:

1. The ability to logically or physically disable any local and network interfaces that are not necessary for the core functionality of the device
2. The ability to logically restrict access to each network interface to only authorized entities (e.g., device authentication, user authentication)
3. Configuration settings for use with the Device Configuration capability including, but not limited to, the ability to enable, disable, and adjust thresholds for any ability the device might have to lock or disable an account or to delay additional authentication attempts after too many failed authentication attempts

ETSI Minimize exposed attack surfaces:

* Provision 5.6-1: All unused network and logical interfaces shall be disabled.
* Provision 5.6-2: In the initialized state, the network interfaces of the device shall minimize the unauthenticated disclosure of security-relevant information.
* Provision 5.6-5: The manufacturer should only enable software services that are used or required for the intended use or operation of the device.
* Provision 5.6-6: Code should be minimized to the functionality necessary for the service/device to operate.
* Provision 5.6-7: Software should run with least necessary privileges, taking account of both security and functionality.

These are procedural requirements, rather than a protocol or document requirement.

### Default Unique Passwords

ENISA GP-TM-09: Establish hard to crack, device-individual default passwords.

ETSI Provision 5.1-1: Where passwords are used and in any state other than the factory default, all consumer IoT device passwords shall be unique per device or defined by the user.

This is a procedural requirement, rather than a protocol or document requirement.

## Data Protection

The data protection requirements are largely procedural/architectural. While this memo can recommend using TEEs to protect data, and TEEP ({{I-D.ietf-teep-architecture}}) to manage TEEs, implementors must choose to architect their software in such a way that TEEs are helpful in meeting these requirements.

ENISA Data Protection requirements:

* GP-TM-10: Personal data must be collected and processed fairly and lawfully, it should never be collected and processed without the data subject's consent.
* GP-TM-11: Make sure that personal data is used for the specified purposes for which they were collected, and that any further processing of personal data is compatible and that the data subjects are well informed.
* GP-TM-12: Minimise the data collected and retained.
* GP-TM-13: IoT stakeholders must be compliant with the EU General Data Protection Regulation (GDPR).
* GP-TM-14: Users of IoT products and services must be able to exercise their rights to information, access, erasure, rectification, data portability, restriction of processing, objection to processing, and their right not to be evaluated on the basis of automated processing.

NIST Data Protection:

1. The ability to use demonstrably secure cryptographic modules for standardized cryptographic algorithms (e.g., encryption with authentication, cryptographic hashes, digital signature validation) to prevent the confidentiality and integrity of the device’s stored and transmitted data from being compromised
2. The ability for authorized entities to render all data on the device inaccessible by all entities, whether previously authorized or not (e.g., through a wipe of internal storage, destruction of cryptographic keys for encrypted data)
3. Configuration settings for use with the Device Configuration capability including, but not limited to, the ability for authorized entities to configure the cryptography use itself, such as choosing a key length

ETSI Data Protection requirements:

* Provision 5.8-3: All external sensing capabilities of the device shall be documented in an accessible way that is clear and transparent for the user.
* Provision 5.11-1: The user shall be provided with functionality such that user data can be erased from the device in a simple manner.
* Provision 5.11-2: The consumer should be provided with functionality on the device such that personal data can be removed from associated services in a simple manner.
* Provision 5.11-3: Users should be given clear instructions on how to delete their personal data.
* Provision 5.11-4: Users should be provided with clear confirmation that personal data has been deleted from services, devices and applications.
* Provision 6-1: The manufacturer shall provide consumers with clear and transparent information about what personal data is processed, how it is being used, by whom, and for what purposes, for each device and service. This also applies to third parties that can be involved, including advertisers.
* Provision 6-2: Where personal data is processed on the basis of consumers' consent, this consent shall be obtained in a valid way.
* Provision 6-3: Consumers who gave consent for the processing of their personal data shall have the capability to withdraw it at any time.
* Provision 6-4: If telemetry data is collected from consumer IoT devices and services, the processing of personal data should be kept to the minimum necessary for the intended functionality.
* Provision 6-5: If telemetry data is collected from consumer IoT devices and services, consumers shall be provided with information on what telemetry data is collected, how it is being used, by whom, and for what purposes.


## System Safety and Reliability

Safety and reliability requirements are procedural/architectural. Implementors should ensure they have processes and architectures in place to meet these requirements.

ENISA Safety and Reliability requirements:

* GP-TM-15: Design with system and operational disruption in mind, preventing the system from causing an unacceptable risk of injury or physical damage.
* GP-TM-16: Mechanisms for self-diagnosis and self-repair/healing to recover from failure, malfunction or a compromised state.
* GP-TM-17: Ensure standalone operation - essential features should continue to work with a loss of communications and chronicle negative impacts from compromised devices or cloud-based systems.

## Authentication

ETSI architectural requirements:

* Provision 5.1-4 Where a user can authenticate against a device, the device shall provide to the user or an administrator a simple mechanism to change the authentication value used.
* Provision 5.1-5 When the device is not a constrained device, it shall have a mechanism available which makes brute-force attacks on authentication mechanisms via network interfaces impracticable.

EST ({{https://datatracker.ietf.org/doc/html/rfc7030}}) and LwM2M Bootstrap ({{LwM2M}}) provide a mechanism to replace trust anchors (manage trust/trust relationships) and perform other forms of credential management (Provision 5.1-4).

### Align Authentication Schemes with Threat Models

ENISA GP-TM-21: Design the authentication and authorisation schemes (unique per device) based on the system-level threat models.

This is a procedural / architectural requirement.

### Password Rules

ENISA applies the following requirements to Password-based authentication:

* GP-TM-22: Ensure that default passwords and even default usernames are changed during the initial setup, and that weak, null or blank passwords are not allowed.
* GP-TM-23: Authentication mechanisms must use strong passwords or personal identification numbers (PINs), and should consider using two-factor authentication (2FA) or multi-factor authentication (MFA) like Smartphones, Biometrics, etc., on top of certificates.
* GP-TM-24: Authentication credentials shall be salted, hashed and/or encrypted.
* GP-TM-25: Protect against 'brute force' and/or other abusive login attempts. This protection should also consider keys stored in devices.
* GP-TM-26: Ensure password recovery or reset mechanism is robust and does not supply an attacker with information indicating a valid account. The same applies to key update and recovery mechanisms.

ETSI applies a the following requirements to password-based authentication: 

* Provision 5.1-1: Where passwords are used and in any state other than the factory default, all consumer IoT device passwords shall be unique per device or defined by the user.
* Provision 5.1-2 Where pre-installed unique per device passwords are used, these shall be generated with a mechanism that reduces the risk of automated attacks against a class or type of device.

As an alternative, implementors are encouraged to consider passwordless schemes, such as FIDO.

## Authorisation

### Principle of Least Privilege

ENISA GP-TM-27: Limit the actions allowed for a given system by Implementing fine-grained authorisation mechanisms and using the Principle of least privilege (POLP): applications must operate at the lowest privilege level possible.

This is a procedural / architectural requirement, however at the network level, this can be implemented using Manufacturer Usage Descriptions (see {{RFC8520}}).

### Software Isolation

ENISA GP-TM-28: Device firmware should be designed to isolate privileged code, processes and data from portions of the firmware that do not need access to them. Device hardware should provide isolation concepts to prevent unprivileged from accessing security sensitive code.

Implementors should use TEEs to address this requirement. The provisioning and management of TEEs can be accomplished using TEEP (see {{I-D.ietf-teep-architecture}}).

ETSI Provision 5.6-8: The device should include a hardware-level access control mechanism for memory.

Implementors should enable and correctly configure the MPU(s) and MMU(s) that are present in most devices.

### Access Control

ENISA Requirements: 

* GP-TM-29: Data integrity and confidentiality must be enforced by access controls. When the subject requesting access has been authorised to access particular processes, it is necessary to enforce the defined security policy.
* GP-TM-30: Ensure a context-based security and privacy that reflects different levels of importance.

These requirements are complex and require a variety of technologies to implement. Use of TEEs can provide a building block for these requirements, but is not sufficient in itself to meet these requiremnents.

ETSI Requirements:

* Provision 5.5-4: Access to device functionality via a network interface in the initialized state should only be possible after authentication on that interface.
* Provision 5.5-5: Device functionality that allows security-relevant changes in configuration via a network interface shall only be accessible after authentication. The exception is for network service protocols that are relied upon by the device and where the manufacturer cannot guarantee what configuration will be required for the device to operate.
* Provision 5.5-5: Device functionality that allows security-relevant changes in configuration via a network interface shall only be accessible after authentication. The exception is for network service protocols that are relied upon by the device and where the manufacturer cannot guarantee what configuration will be required for the device to operate.

## Environmental and Physical Security

ENISA defines the following physical security requirements. These are hardware-architectural requirements and not covered by protocol and format specifications.

* GP-TM-31: Measures for tamper protection and detection. Detection and reaction to hardware
tampering should not rely on network connectivity.
* GP-TM-32: Ensure that the device cannot be easily disassembled and that the data storage medium is encrypted at rest and cannot be easily removed.
* GP-TM-33: Ensure that devices only feature the essential physical external ports (such as USB) necessary for them to function and that the test/debug modes are secure, so they cannot be used to maliciously access the devices. In general, lock down physical ports to only trusted connections.

ETSI defines the following physical security requirements:

* Provision 5.6-3: Device hardware should not unnecessarily expose physical interfaces to attack.
* Provision 5.6-4: Where a debug interface is physically accessible, it shall be disabled in software.

## Cryptography

ENISA makes the following architectural cryptography requirements for IoT devices:

* GP-TM-34: Ensure a proper and effective use of cryptography to protect the confidentiality, authenticity and/or integrity of data and information (including control messages), in transit and in rest. Ensure the proper selection of standard and strong encryption algorithms and strong keys, and disable insecure protocols. Verify the robustness of the implementation.
* GP-TM-35: Cryptographic keys must be securely managed.
* GP-TM-36: Build devices to be compatible with lightweight encryption and security techniques.
* GP-TM-37: Support scalable key management schemes.

ETSI makes the following architectural cryptography requirement for IoT devices: 

* Provision 5.1-3: Authentication mechanisms used to authenticate users against a device shall use best practice cryptography, appropriate to the properties of the technology, risk and usage.
* Provision 5.4-3: Hard-coded critical security parameters in device software source code shall not be used.
* Provision 5.4-4: Any critical security parameters used for integrity and authenticity checks of software updates and for protection of communication with associated services in device software shall be unique per device and shall be produced with a mechanism that reduces the risk of automated attacks against classes of devices.
* Provision 5.5-3: Cryptographic algorithms and primitives should be updateable.

## Secure and Trusted Communications

### Data Security

ENISA GP-TM-38: Guarantee the different security aspects -confidentiality (privacy), integrity, availability and authenticity- of the information in transit on the networks or stored in the IoT application or in the Cloud.

ETSI Data Security Requirements:

* Provision 5.5-6: Critical security parameters should be encrypted in transit, with such encryption appropriate to the properties of the technology, risk and usage.
* Provision 5.5-7 The consumer IoT device shall protect the confidentiality of critical security parameters that are communicated via remotely accessible network interfaces.
* Provision 5.5-8 The manufacturer shall follow secure management processes for critical security parameters that relate to the device.
* Provision 5.8-1 The confidentiality of personal data transiting between a device and a service, especially associated services, should be protected, with best practice cryptography.
* Provision 5.8-2 The confidentiality of sensitive personal data communicated between the device and associated services shall be protected, with cryptography appropriate to the properties of the technology and usage.

This Data Security requirement can be fulfilled using COSE {{RFC8152}} for ensuring the authenticity, integrity, and confidentiality of data either in transit or at rest. Secure Transport (see {{secure-transport}}) technologies can be used to protect data in transit.

### Secure Transport {#secure-transport}

ENISA Requirements: 

* GP-TM-39: Ensure that communication security is provided using state-of-the-art, standardised security protocols, such as TLS for encryption.
* GP-TM-40: Ensure credentials are not exposed in internal or external network traffic.

ETSI Requirements:

* Provision 5.5-1: The consumer IoT device shall use best practice cryptography to communicate securely.
* Provision 5.5-2: The consumer IoT device should use reviewed or evaluated implementations to deliver network and security functionalities, particularly in the field of cryptography.
* Provision 5.5-4: Access to device functionality via a network interface in the initialized state should only be possible after authentication on that interface.

This requirement is satisfied by several standards:

* TLS ({{RFC8446}}).
* DTLS ({{RFC9147}}).
* QUIC ({{RFC9000}}).
* OSCORE ({{RFC9203}}).

### Data Authenticity

ENISA GP-TM-41: Guarantee data authenticity to enable reliable exchanges from data emission to data reception. Data should always be signed whenever and wherever it is captured and stored.

The authenticity of data can be protected using COSE {{RFC8152}}.

ENISA GP-TM-42: Do not trust data received and always verify any interconnections. Discover, identify and verify/authenticate the devices connected to the network before trust can be established, and preserve
their integrity for reliable solutions and services.

Verifying communication partners can be done in many ways. Key technologies supporting authentication of communication partners are:

* RATS: Remote attestation of a communication partner (See {{I-D.ietf-rats-architecture}}).
* TLS/DTLS: Mutual authentication of communication partners (See {{RFC8446}} / {{RFC9147}}).
* ATLS: Application-layer TLS for authenticating a connection that may traverse multiple secure transport connections.
* Attested TLS: The use of attestation in session establishment in TLS (See {{I-D.fossati-tls-attestation}}).

### Least Privilege Communication

ENISA GP-TM-43: IoT devices should be restrictive rather than permissive in communicating.

This Requirement can be enabled and enforced using Manufacturer Usage Descriptions, which codify expected communication (See {{RFC8520}})

ENISA GP-TM-44: Make intentional connections. Prevent unauthorised connections to it or other devices the
product is connected to, at all levels of the protocols.

This requirement can be satisfied through authenticating connections (TLS / DTLS mutual authentication. See {{RFC8446}} / {{RFC9147}}) and declaring communication patterns (Manufacturer Usage Descriptions. See {{RFC8520}})

Architectural / Procedural requirements: 

* ENISA GP-TM-45: Disable specific ports and/or network connections for selective connectivity.
* ENISA GP-TM-46: Rate limiting. Controlling the traffic sent or received by a network to reduce the risk of automated attacks.

## Secure Interfaces and network services

ENISA Architectural / Procedural requirements: 

* GP-TM-47: Risk Segmentation. Splitting network elements into separate components to help isolate security breaches and minimise the overall risk.
* GP-TM-48: Protocols should be designed to ensure that, if a single device is compromised, it does not affect the whole set.
* GP-TM-49: Avoid provisioning the same secret key in an entire product family, since compromising a single device would be enough to expose the rest of the product family.
* GP-TM-50: Ensure only necessary ports are exposed and available.
* GP-TM-51: Implement a DDoS-resistant and Load-Balancing infrastructure.
* GP-TM-53: Avoid security issues when designing error messages.

ETSI Architectural requirements:

* Provision 5.1-5 When the device is not a constrained device, it shall have a mechanism available which makes brute-force attacks on authentication mechanisms via network interfaces impracticable.

### Encrypted User Sessions

ENISA GP-TM-52: Ensure web interfaces fully encrypt the user session, from the device to the backend services, and that they are not susceptible to XSS, CSRF, SQL injection, etc.

This requirement can be partially satisfied through use of TLS or QUIC (See {{RFC8446}} and {{RFC9000}})

## Secure input and output handling

Architectural / Procedural requirements: 

ENISA GP-TM-54: Data input validation (ensuring that data is safe prior to use) and output filtering.

ETSI Provision 5.13-1: The consumer IoT device software shall validate data input via user interfaces or transferred via Application Programming Interfaces (APIs) or between networks in services and devices.

## Logging

Architectural / Procedural requirements: 

ENISA GP-TM-55: Implement a logging system that records events relating to user authentication, management of accounts and access rights, modifications to security rules, and the functioning of the system. Logs must be preserved on durable storage and retrievable via authenticated connections.

NIST Cybersecurity State Awareness

1. The ability to report the device’s cybersecurity state
2. The ability to differentiate between when a device will likely operate as expected from when it may be in a degraded cybersecurity state
3. The ability to restrict access to the state indicator so only authorized entities can view it
4. The ability to prevent any entities (authorized or unauthorized) from editing the state except for those entities that are responsible for maintaining the device’s state information
5. The ability to make the state information available to a service on another device, such as an event/state log server

ETSI defines the following logging requirements:

* Provision 5.7-2: If an unauthorized change is detected to the software, the device should alert the user and/or administrator to the issue and should not connect to wider networks than those necessary to perform the alerting function.

Certain logs and indicators of cybersecurity state can be transported via RATS: See {{I-D.ietf-rats-eat}}. Where associated with SUIT firmware updates, logs can be transported using SUIT Reports. See {{I-D.ietf-suit-report}}. 

## Monitoring and Auditing

ENISA Architectural / Procedural requirements: 

* ENISA GP-TM-56: Implement regular monitoring to verify the device behaviour, to detect malware and to discover integrity errors.
* ENISA GP-TM-57: Conduct periodic audits and reviews of security controls to ensure that the controls are effective. Perform penetration tests at least biannually.

ETSI Architectural / Procedural requirements:

* Provision 5.2-1: The manufacturer shall make a vulnerability disclosure policy publicly available.
* Provision 5.2-2: Disclosed vulnerabilities should be acted on in a timely manner.
* Provision 5.2-3: Manufacturers should continually monitor for, identify and rectify security vulnerabilities within products and services they sell, produce, have produced and services they operate during the defined support period.
* Provision 5.6-9: The manufacturer should follow secure development processes for software deployed on the device.
* Provision 5.10-1 If telemetry data is collected from consumer IoT devices and services, such as usage and measurement data, it should be examined for security anomalies.

Supply Chain Integrity, Transparency, and Trust ({{I-D.ietf-scitt-architecture}}) enables monitoring for inclusion of disclosed vulnerabilities within products and services, so can be used to satisfy Provision 5.2-3.

# Security Considerations

No additional security considerations are required; they are laid out in the preceeding sections.

--- back

