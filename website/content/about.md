+++
title = "About Bouncy GPG"
date = "2017-10-10"
menu = "main"
+++

Cryptography is a powerful tool to implement some very tricky business requirements. 
Requirement that include the words _confidentiality_,  _integrity_, or _availability_ are very likely to have efficient and effective solutions that leverage cryptography. 

These requirements have many sources, and cryptography is not always the obvious answer. Here are some use cases that show how cryptography can help to solve problems seemingly unrelated to cryptography:

* Minimise storage cost by using (public) cloud storage for storing large data sets
* Show due diligence by provably protecting personal data (bonus: many laws explicitly name cryptography as a valid solution)
* Prevent damage to the business by detecting unauthorised manipulation of critical data
* Tamper proof audit logs

The tutorials, examples, and documentation on this site are aimed at the application programmer that is tasked to design or implement these requirements.


Most sources that teach cryptography aim to explain the inner workings of cryptographic primitives.
For the average programming task this is a bit like having first to learn how to operate a nationwide powergrid before being allowed to plug in the plug of a TV. This site is different as it aims to present **patterns** for solving these problems.

### Bouncy GPG

Bouncy GPG is a java library that provides an opinionated API for cryptographic use cases. It also strives to provide the best documentation for programmers to solve problems without shooting theirselves in the foot.

Bouncy GPG  is licensed under the very permissive <a href="https://www.apache.org/licenses/LICENSE-2.0.html"><img src="https://img.shields.io/badge/license-APACHE%202.0-brightgreen.svg" alt="license"  style="width: auto; height: auto; display: inline; margin: 0"/></a>.

Learn more and contribute on [<i class='fa fa-github'></i>GitHub](https://github.com/neuhalje/bouncy-gpg).

The website is generated with [hugo](https://gohugo.io) and the beautiful [docdock theme](https://github.com/vjeantet/hugo-theme-docdock).

All code samples are actually executed at build time by [concordion](https://github.com/concordion) and the [concordion-api-documentation-extension](https://github.com/concordion/concordion-api-documentation-extension).

_Pull requests welcome!_

