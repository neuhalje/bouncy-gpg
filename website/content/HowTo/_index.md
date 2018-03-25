+++
title = "HowTo"
+++

Most sources that teach cryptography aim to explain the inner workings of cryptographic primitives.
For the average programming task this is a bit like having first to learn how to operate a nationwide powergrid before being allowed to plug in the plug of a TV. This site is different as it aims to present **patterns** for solving these problems.

Even with a library like BouncyGPG it is impossible to correctly use the cryptography toolbox without a bit of theoretical background. The HOWTOs will give solid implementation guidelines regarding selected use cases.

The provide example code can act as starting point for your implementations.

{{% notice warning %}}
Reading the use cases will provide you with enough information to implement them for "normal security" applications. For high security applications, e.g. when the life of people is at stake involve a cryptographer!
{{% /notice %}}

## Use Cases
{{% children description="true" depth="1"  %}}

