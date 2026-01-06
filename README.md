





Working spec: https://docs.google.com/document/d/11NUBTn3vD0obePboUQ74rO-32fDkaS5LsNgQqkqjJok/edit?tab=t.0



Key 1:
```json
{
	"alg":"ES256",
	"iat":1623132000,
	"kid":"Zami's Majuscule Key.",
	"d":"bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
	"tmb":"cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
	"x":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
}
```



```json
{
    "alg": "ES384",
    "iat": 1767197339,
    "kid": "My Cyphr.me Key.",
    "tmb": "oKirqNU6ucGqRRsYeuZhQO-VzGAxI_fS9Ih6sR60B5fJmpvwqoK2Z8OmXk33zv01",
    "x": "piWu2-X81abA1ScSdzXPY4AghjsABCsaXfRL3WVsxepbwxHCvyToWGtzpmrih8BDNHtMKiWpC8o6WCYgLv-gEJIpMN7rNEvZ6AgosvJ8Rcpx8y0AUcM5GDHlyQp_hHuv",
    "d": "zdDVJ8humAHjHPUoUOZ1wquv36UZAXsFMwKw_MARHA2VoBjTAOEmefkrULNQ1Fd2"
}
```



```json
{
	"alg":"ES256",
	"iat":1623132000,
	"kid":"Zami's Majuscule Key.",
	"d":"bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
	"tmb":"cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
	"x":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
}
```


Genesis Transaction
```json
{
  "pay": {
    "alg": "ES256",
    "iat": 1628181264,
    "tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
    "typ": "cyphr.me/cyphrpass/account/create",
    "id": "RpMM4_lU6jCj3asZEtIFyYqPjC2L6mlucl7VGMvAuno"
  },
  "sig": "OigwNSWuPbzkZ6IVaK8MSw5kL61M2cdvuo7HmcfGUJMsRq9I1aD1y1tMwWFC3BmUu8x_AvFR9BoQ3DTxjNLnpw"
}
```

Genesis with `key`
```json
{
	"pay": {
		"alg": "ES256",
		"iat": 1628181264,
		"tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
		"typ": "cyphr.me/cyphrpass/account/create",
		"id": "RpMM4_lU6jCj3asZEtIFyYqPjC2L6mlucl7VGMvAuno"
	},
	"sig": "OigwNSWuPbzkZ6IVaK8MSw5kL61M2cdvuo7HmcfGUJMsRq9I1aD1y1tMwWFC3BmUu8x_AvFR9BoQ3DTxjNLnpw",
	"key":{
		"alg":"ES256",
		"kid":"Zami's Majuscule Key.",
		"tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
		"x":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
	}
}
```











```json





{
	"pay": {
		"alg": "ES256",
		"iat": 1628181264,
		"tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
		"typ": "cyphr.me/key/upsert",
		"id: "zxcLp3BEYYoAZxM9QlV7lS4o3Jn1T0dz9L0pWPZJnIs"
	}
}






For this key:
"key": {
"alg": "ES256",
"iat": 1624472390,
"tmb": "zxcLp3BEYYoAZxM9QlV7lS4o3Jn1T0dz9L0pWPZJnIs",
"kid": "Second Key.",
"x": "F-uHX_..."
}


{
	"pay": {
		"alg": "ES256",
		"iat": 1628181264,
		"tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk",
		"typ": "cyphr.me/cyphrpass/key/upsert",
		"id: "zxcLp3BEYYoAZxM9QlV7lS4o3Jn1T0dz9L0pWPZJnIs"
	}
}




```