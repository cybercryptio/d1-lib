# CYBERCRYPT D1 Library - Symmetric Searchable Encryption user manual 

This document explains how the Symmetric Searchable Encryption (SSE) implemented in the D1 Library works.

## SSE scheme

SSE allows users to search for keywords in encrypted data without decrypting it.

The SSE scheme provides 3 algorithms, `Add`, `Search`, and `Delete`.

(Usually, the elements in a hash map are called keys and values. In this context the keys are referred to as *labels* in order to not mix them up with encryption keys.) 

* `Add` takes as input a keyword and an identifier (e.g. a document ID), computes an encrypted label -> value pair, and stores it in a secure index. The label -> value pair maps the given keyword to the given identifier. Every time a specific keyword is mapped to a new identifier, a slightly different version of the same label is used. That makes it possible to easily find all the identifiers that the keyword is mapped to, using a `Search` query.
* `Search` takes as input a keyword, computes the corresponding encrypted labels, finds the encrypted values in the secure index that the labels map to, decrypts them, and returns the plaintext identifiers to the user.
* `Delete` takes as input a keyword and an identifier, computes the encrypted label -> value pair, and deletes that pair from the secure index. Note that `Delete` does not remove the keyword from the identifier, it only removes the keyword/identifier pair from the secure index.

Note that keywords and identifiers never leave the D1 Library without being encrypted.

## Usage
Consider a scenario with 3 different documents identified as `id1`, `id2`, `id3`, respectively. The documents contain, among other words, the following keywords, and the keyword/identifier pairs can be added to the secure index.

* `id1` contains the keyword `keyword1`. 
* `id1` and `id2` both contain the keyword `keyword2`.
* `id2` contains the keyword `keyword3`.
* `id1`, `id2`, and `id3` all contain the keyword `keyword4`.

Given a keyword for a `Search` query, all the identifiers that contain the given keyword can then be identified, even when the documents are encrypted. Below, a secure index is initialized, and the keyword/identifier pairs listed above are added to the secure index.

```go
secureIndex := NewSecureIndex(&keyProvider, &ioProvider, &idProvider)
```
Note that a valid `token` must be provided. A `token` is valid if the caller can use it to be authenticated by the Identity Provider and to be authorized to use the secure index.

```go
if err := secureIndex.Add(token, "keyword1", "id1"); err != nil {
    return err
}
if err = secureIndex.Add(token, "keyword2", "id1"); err != nil {
    return err
}
if err = secureIndex.Add(token, "keyword2", "id2"); err != nil {
    return err
}
if err = secureIndex.Add(token, "keyword3", "id2"); err != nil {
    return err
}
if err = secureIndex.Add(token, "keyword4", "id1"); err != nil {
    return err
}
if err = secureIndex.Add(token, "keyword4", "id2"); err != nil {
    return err
}
if err = secureIndex.Add(token, "keyword4", "id3"); err != nil {
    return err
}
```

A `Search` query can be used to identify which documents contain e.g. `keyword4`:

```go
IDs, err := secureIndex.Search(token, "keyword4")
if err != nil {
    return err
}

fmt.Println(IDs)
```

```go
Out:    ["id1", "id2", "id3"]
```

A keyword can be deleted from a document, below `keyword4` is deleted from `id1`.
```go
err = secureIndex.Delete(token, "keyword4", "id1")
if err != nil {
    return err
}
```

After the `Delete` query, the `Search` query will now return a different output:
```go
IDs, err = secureIndex.Search(token, "keyword4")
if err != nil {
    return err
}

fmt.Println(IDs)
```

```go
Out:    ["id2", "id3"]
```

## Implementation

In this section, some more technical details about the implementation are given.

Given a keyword and an identifer for an `Add` query, a label is computed based on the keyword as well as on a *counter* (explained below), and an Identifier struct representing the identifier is created. The label is then mapped to the Identifier as shown below, and the "label -> Identifier" correlation is stored in the secure index. The Identifier is sealed before it is stored in order to avoid having plaintext keywords or identifiers outside of the D1 Library. Note that the keyword is used to seal the Identifier which means that the sealed Identifier can only be unsealed if the keyword is known.

In storage:
```go
label(keyword, counter) -> sealed Identifier(keyword, identifier)
```

An Identifier struct (before seal) contains the identifier itself as well as a `NextCounter` as shown below. `NextCounter` is used to compute the next label based on the same keyword. As explained in the [SSE scheme](#sse-scheme) section, every time a specific keyword is mapped to a new identifier, a slightly different version of the same label is used, i.e. the next label maps the same keyword to another sealed Identifier. If the keyword has only been mapped to a single identifier, then its sealed Identifier's `NextCounter` is 0. Given a keyword for a `Search` query, all the identifiers that it maps to, i.e. all the identifiers that contain the given keyword, are then easily found by going through the chain of `NextCounter`'s and computing the corresponding label for each counter. The chain is illustrated below. It is ensured that the counter used to compute the first label in the chain is always known.

```go
Identifier = {
    Identifier:   "id1",
    NextCounter:  1,
}
```

![sse-chain.png](images/sse-chain.png)

Given a keyword and an identifer for a `Delete` query, the correct label/sealed Identifier pair is found and deleted. The chain remains intact as the previous `NextCounter` is updated to the deleted sealed Identifier's `NextCounter`.