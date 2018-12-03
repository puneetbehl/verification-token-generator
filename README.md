# Generate JWT Token For Registration Verification Email

This is the sample application which generates and validate JWT token. You can either generate a Plain JWT or Sign it using a 256bit secret key. Following is the supported configuration:

```yaml
micronaut:
  registration:
    token:
      jwt:
        expirationInSeconds: 3600
        secret: VkYp3s6v9y/B?E(H+MbQeThWmZq4t7w!
        algorithm: HS256
        base64: false
```

* Only the HS256, HS384 and HS512 algorithms are supported for HMac signature `algorithm`. 
* Also, you could also encode secret using `BASE64`.
