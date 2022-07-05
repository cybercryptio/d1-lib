# CYBERCRYPT D1 library explainer

This document defines the main concepts and use cases for the D1 library.

# Concepts

## *Provider concepts*

**Providers** are interfaces that the library relies on for delivering functionality that is necessary, but orthogonal, to the implemented cryptographic mechanisms. The users of the library can plug in various implementations of the same **Provider** behavior, depending on their use-case.

![providers.png](images/providers.png)

### Key Provider

The **Key Provider** is the source of cryptographic key material for the library. Implementations of its [interface](https://pkg.go.dev/github.com/cybercryptio/d1-lib/key#Provider) must be able to provide four 256-bit keys: Key Encryption Key (KEK), Access Encryption Key (AEK), Token Encryption Key (TEK), Index Encryption Key (IEK). For more information about keys and their uses [see our Security Architecture Documentation](TODO).

### IO Provider

The **IO Provider** acts as a source and destination for the [encrypted data](#data-concepts) produced/consumed by the library. Implementations of its [interface](https://pkg.go.dev/github.com/cybercryptio/d1-lib/io#Provider) could use various types of storage, for example: blob storage, relational databases, queues, in-memory storage, etc.

### Identity Provider

The **Identity Provider** is the source of identifying information about the caller of the library. It allows the library to validate [**Identity Tokens**](#identity-token) and fetch their corresponding [**Identity**](#identity) objects. Implementations of its [interface](https://pkg.go.dev/github.com/cybercryptio/d1-lib/id#Provider) could use various Identity and Access Management (IAM) solutions such as SAML or OpenID. For easily getting up and running, the library implements a [**Standalone Identity Provider**](#standalone-identity-provider).

### Identity

An **Identity** is an object that contains data about the caller of the library. This data includes:
- a Universally Unique Identifier (UUID) as defined in the [RFC-4122](https://datatracker.ietf.org/doc/html/rfc4122) standard;
- the [**Scopes**](#scope) of the caller;
- the **Groups** that the caller belongs to.

### Scope

**Scopes** are used to control access to the [**Encrypted Objects**](#object). **Identities** have associated **Scopes**, and they can only perform operations on [**Data**](#data-concepts) when they have the required scopes. [See our documentation for examples of how to enforce access control using the D1 library.](https://pkg.go.dev/github.com/cybercryptio/d1-lib#example-package-AccessControl)

### Identity Token

**Identity Tokens** are strings provided by the library callers so that they can be authenticated by the **Identity Provider**. When authenticating a call, the **Identity Provider** validates the token and returns an **Identity** object with the caller data. These tokens should preferably be opaque to anyone but the **Identity Provider**.

### Standalone Identity Provider

The **Standalone Identity Provider** is an **Identity Provider** implementation designed to easily get up and running for the library users who do not have an existing IAM system in place. It provides the following functionalities:
- Creating and managing **Users**, **Groups** and **Identity Tokens**;
- Translating between **Identity Tokens** and **Identities**;
- Storing the user data with the configured **IO Provider**;
- Encrypting **Users**, **Groups** and **Identity Tokens** using the configured encryption keys: User Encryption Key (UEK), Group Encryption Key (GEK), Token Encryption Key (TEK).

#### User

A **User** is a data structure used by the **Standalone Identity Provider** to store data about the callers of the library. A **User** authenticates to the **Standalone Identity Provider** with a Universally Unique Identifier (UUID) and a password provided upon user creation. A **User** structure contains the salt and hash of the **User's** password, its **Scopes** and a set of **Groups** that the **User** is a member of.

#### Group

A **Group** is a data structure used by the **Standalone Identity Provider** to manage sets of **Users**. **Groups** have their own associated **Scopes** and can be used to manage access to [**Encrypted Objects**](#object) for multiple users at a time.

Only **Users** who are part of a **Group** are allowed to modify its members or **Scopes**.

## *Data concepts*

### Object

An **Object** contains binary data owned by a **User** which can be encrypted resulting in an **Encrypted Object** and an **Access List**. 

Besides the binary data itself, an **Object** can optionally contain some additional associated data, which will not be encrypted in the **Encrypted Object**, but it’s integrity is checked in the decryption process. This associated data can be used, for example, for indexing encrypted objects.

### Access List

Each **Encrypted Object** has a corresponding **Access List**, which is used to control who is able to decrypt the object. **Access Lists** are encrypted, and they contain in their ciphertext a set of IDs of the **Groups** which are allowed to decrypt the corresponding **Encrypted Object**.

Only **Users** who are part of the **Access List** are allowed to modify it. By default, an **Access List** has only the ID of the default **Group** of the **User** who created it.

### Token

A **Token** represents some arbitrary encrypted data with an attached expiration time. Data inside of a **Token** is not access controlled, i.e. it can be decrypted by any caller of the library as long as the expiration time hasn’t passed.

### Search Index

A **Search Index** is an object used to map keywords to **Encrypted Objects**, allowing the ability to search over encrypted data. The **Search Index** cryptographically hides the contents and the number of keywords and **Encrypted Objects**, as well as the mapping between them.

# Use cases

The D1 library allows **Users** to encrypt **Objects** and to restrict the ability to decrypt only for specific user **Groups** through the **Access Lists**. Additionally, the library offers support for creating encrypted security tokens and for searching over encrypted data.

## Application layer encryption

The majority of software applications use encryption for securing data in-transit and at-rest. This means that the data is protected only while being transferred over the network and while being stored, and any compromised software or machine in the data path can leak sensitive data. Application layer encryption reduces the attack surface by encrypting data end-to-end, inside the applications that create and consume it.

The D1 library provides cryptographic functions for protecting data and enforcing access control, which can be used to implement application layer encryption.

![ale.svg](images/ale.svg)

## Storing data in untrusted locations

Storing sensitive data in the cloud can be risky as you have to trust that the cloud provider has good security protections to avoid unauthorized access to the data. Moreover, you have to make sure that you configure the security mechanisms offered by the cloud provider properly which can in and of itself be challenging in multi-cloud setups.

The D1 library can be used to encrypt data at the application layer, before being sent to the storage, allowing its users to not rely only on the cloud providers to protect their sensitive data.

![encrypted-store.svg](images/encrypted-store.svg)

## Granular access control

The D1 library can be used to implement various access control schemes for protecting data and ensuring that only certain applications/users can decrypt it. This can for example be used to ensure that applications that produce data can encrypt it, but cannot read it, minimizing the risk of a data leak if that application is compromised. 

![access-control.svg](images/access-control.svg)

## Searchable encrypted data

The D1 library implements Searchable Symmetric Encryption which allows users to search for keywords in encrypted data without decrypting it. The contents of the Data Objects and the number of keywords are hidden from the searching party.

![sse.svg](images/sse.svg)
