# CYBERCRYPT D1 library explainer

This document defines the main concepts and use cases for the D1 library.

# Concepts

### User

A **User** represents the identity of the caller of the library. Every **User** is represented by a Universally Unique Identifier (UUID) as defined in the [RFC-4122](https://datatracker.ietf.org/doc/html/rfc4122) standard. A **User** can be part of one or more **Groups**.

### Group

A **Group** represents a set of **Users**. Every **Group** is represented by a Universally Unique Identifier (UUID) as defined in the [RFC-4122](https://datatracker.ietf.org/doc/html/rfc4122) standard. Every **Group** has at least one **User**. Each **User** has an associated default **Group** which is created upon creating the **User** and which initially contains only the ID of the **User**.

**Groups** can contain arbitrary data that is common to its **Users**. This data can be used, for example, to attach roles or permissions to groups in order to implement role-based access control schemes. 

Only **Users** who are part of a **Group** are allowed to modify it. 

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
