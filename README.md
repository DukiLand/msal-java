# MSAL - JAVA

### Microsoft Azure Active Directory Single Sign On : OAuth

src > resources > authentication.properties

아래의 항목들을 Azure SSO와 연결하고자 하는 어플리케이션 환경에 맞게 수정해야 합니다.

`aad.clientId` Azure SSO 어플리케이션 ID

`aad.secret` Azure SSO 어플리케이션에서 발급한 비밀키

`aad.authority` https://login.microsoftonline.com/{테넌트ID}

`app.homePage` 연결시킬 웹 어플리케이션 주소

`app.redirectEndpoint` 로그인 후 리다이렉트될 웹 어플리케이션 주소 : Azure SSO 어플리케이션 리디렉션 URI와 같아야합니다.