
# Padded Length Bytes - Passing BER Encoded Certificates

The three certificates in this directory are all signed using:

ta.pem

Only one of them (a.pem) is actually valid

a.pem

Both b.pem and c.pem have been modified to produce BER encodings allowing the adding of extra bytes to the length of octet strings. In the b the length is encoded as long form, when the short form is used. In the c case an extra 0 byte has been added to the length.

DER encoding requires that the length of primitives is always encoded using the minimum number of bytes. For DER validations anything with extra bytes in lengths should be rejected (in fact OpenJDK rejects the data out of hand on parsing as it's only ever expecting DER input, with Bouncy Castle we're a bit more gracious, we'll read it but then it's rejected on validation). Both b and c should fail to validate.
