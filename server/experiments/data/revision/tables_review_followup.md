# 검토 보완 표 (검증 집합, 파라미터 변경 없음)

## 1. 수치 검증

- CASE_C (최종 설정): {'n': 56, 'benign': 41, 'phishing': 15, 'tp': 11, 'fn': 4, 'fp': 6, 'tn': 35}
- B 개선 전 (W_ML(B)=0.30 전체): {'tp': 245, 'fp': 15, 'tn': 235, 'fn': 5, 'recall': 98.0, 'precision': 94.23, 'f1': 96.08, 'fpr': 6.0, 'accuracy': 96.0}
- B 개선 후 (deep 0.50): {'tp': 245, 'fp': 18, 'tn': 232, 'fn': 5, 'recall': 98.0, 'precision': 93.16, 'f1': 95.52, 'fpr': 7.2, 'accuracy': 95.4}
- 15건 호스트: {'github.io': 12, 'new-set-3.searchsst.info': 1, 'www.roblox.com.ml': 1, 'seu-delivery.food': 1} · URL 에 'clone' 포함 8건
- 라벨별 루트/경로: 정상 root 125/250, 피싱 root 141/250

| α 구간 | URL | 라벨 | 상황 | d/n | p_ML | 변화 |
|---|---|---|---|---|---|---|
| 1.0 → 2.0 | http://sp12ct-hordik-biz-kamsel-frondor.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9949 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-harsok-biz-veldik-pramor.pages.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.992 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-varsor-biz-kendik-zolmar.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.992 | 탐지 |
| 1.0 → 2.0 | https://kukcon-xlognx.godaddysites.com/ | 피싱 | CASE_A_HIGH | 18/92 | 0.9076 | 탐지 |
| 1.0 → 2.0 | http://msbpr5dplix-ycgfnyhy-8c9d4e-qv177a.pages.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.992 | 탐지 |
| 1.0 → 2.0 | http://mhbkt4a51gp-xwldgmja-1e9f5b-mhb96c.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9897 | 탐지 |
| 1.0 → 2.0 | https://furious-aqua-yss2lu8g.edgeone.dev/ | 피싱 | CASE_A_HIGH | 20/92 | 0.9844 | 탐지 |
| 1.0 → 2.0 | http://inspirational-process-593665.framer.app/ | 피싱 | CASE_A_HIGH | 21/92 | 0.9942 | 탐지 |
| 1.0 → 2.0 | https://urlto.me/2ouA9 | 피싱 | CASE_A_HIGH | 20/92 | 0.962 | 탐지 |
| 1.0 → 2.0 | http://webdisk.20-244-0-63.cprapid.com/ | 피싱 | CASE_A_HIGH | 17/92 | 0.9892 | 탐지 |
| 1.0 → 2.0 | http://trezur-start-base-faqs-io.typedream.app/ | 피싱 | CASE_A_HIGH | 17/92 | 0.9538 | 탐지 |
| 1.0 → 2.0 | https://facebookbigeronline.blogspot.com/ | 피싱 | CASE_A_HIGH | 19/92 | 0.5672 | 탐지 |
| 1.0 → 2.0 | https://web-fun-checkout-prototype-uniswap.vercel.app/positions | 피싱 | CASE_A_HIGH | 18/92 | 0.7895 | 탐지 |
| 1.0 → 2.0 | http://hammadbaloch-9.github.io/Facebook | 피싱 | CASE_A_HIGH | 13/95 | 0.9815 | 탐지 |
| 1.0 → 2.0 | https://roblox.com.ug/users/5184319778/profile | 피싱 | CASE_A_HIGH | 24/92 | 0.9703 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-harsik-biz-voldek-pramel.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9888 | 탐지 |
| 1.0 → 2.0 | https://ipfs.io/ipfs/bafybeib65hqaeocurjfgaqozudsqxji7qc5cc2c2ivjl7rdkai52sonm4q | 피싱 | CASE_A_HIGH | 16/92 | 0.9968 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-kelsor-biz-zavmik-prondel.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9917 | 탐지 |
| 1.0 → 2.0 | http://jzkvm81mjwy-tqbrpren-5b8e1f-mh833a.pages.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.9897 | 탐지 |
| 1.0 → 2.0 | http://facebookloginapp.blogspot.com/ | 피싱 | CASE_A_HIGH | 19/92 | 0.9599 | 탐지 |
| 1.0 → 2.0 | https://www.roblox.com.bn/users/889521457001/profile | 피싱 | CASE_A_HIGH | 21/92 | 0.9549 | 탐지 |
| 1.0 → 2.0 | https://comcastupdate.framer.ai/ | 피싱 | CASE_A_HIGH | 21/92 | 0.8397 | 탐지 |
| 1.0 → 2.0 | http://docusine.com/?urid=QcAw22ro3Hy2k-wDLudNKbQwzfsL3yKQLeE7b0_B3wVOgALWCaBAUcacWU3d0KW1AwZwJryjXaGzSZ6kF_7P8EiB-KfPwbFgMIbLsfRV_SyTQ_ekNMip4dClmgKHz0nRtmu4E7r8XYR35AHtn0YAE | 피싱 | CASE_A_HIGH | 17/92 | 0.7275 | 탐지 |
| 1.0 → 2.0 | https://www.roblox.com.bi/games/4960160668/Resting-Place-RP?privateServerLinkCode=44972828233268178052026857992075 | 피싱 | CASE_A_HIGH | 23/92 | 0.5977 | 탐지 |
| 1.0 → 2.0 | https://23x2x32x.pages.dev/ | 피싱 | CASE_A_HIGH | 15/92 | 0.9892 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-kandor-biz-fravmek-lorsik.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9916 | 탐지 |
| 1.0 → 2.0 | http://outlooksereguri365.hstn.me/ | 피싱 | CASE_A_HIGH | 18/92 | 0.8863 | 탐지 |
| 1.0 → 2.0 | http://ok2wt5-3n5b2-o9pq-5pm-3gjs5n.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9981 | 탐지 |
| 1.0 → 2.0 | https://sp12ct-lavrek-biz-prandor-zelsok.pages.dev/ | 피싱 | CASE_A_HIGH | 16/92 | 0.9863 | 탐지 |
| 1.0 → 2.0 | https://www.facebook-verification-system4.blogspot.com/ | 피싱 | CASE_A_HIGH | 17/92 | 0.9015 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-zandek-biz-kelmor-frasik.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9887 | 탐지 |
| 1.0 → 2.0 | https://trk-105.healthanswers.info/ga/click/2-17218745-21-16023-31226-17407-2f0b352bc3-432bcb9b64 | 피싱 | CASE_A_HIGH | 15/92 | 0.9749 | 탐지 |
| 1.0 → 2.0 | https://tinyurl.com/3x4e89ap | 피싱 | CASE_A_HIGH | 15/92 | 0.9909 | 탐지 |
| 1.0 → 2.0 | https://sp12ct-prandor-biz-fravik-lazsel.pages.dev/ | 피싱 | CASE_A_HIGH | 15/92 | 0.9945 | 탐지 |
| 1.0 → 2.0 | https://lost.com-isupport.help/ | 피싱 | CASE_A_HIGH | 19/92 | 0.8778 | 탐지 |
| 1.0 → 2.0 | https://dqb.buzz/dpd | 피싱 | CASE_A_HIGH | 20/92 | 0.8742 | 탐지 |
| 1.0 → 2.0 | https://imtokens.tronscoin.com/ | 피싱 | CASE_A_HIGH | 21/92 | 0.6404 | 탐지 |
| 1.0 → 2.0 | http://esign.social-statements.com/ | 피싱 | CASE_A_HIGH | 18/92 | 0.8684 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-zorsel-biz-karmik-favdok.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9888 | 탐지 |
| 1.0 → 2.0 | http://fuchsia-workshops-221572.framer.app/ | 피싱 | CASE_A_HIGH | 16/92 | 0.9983 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-hormik-biz-zaldek-vansor.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9918 | 탐지 |
| 1.0 → 2.0 | http://bt-internet-108197.weeblysite.com/ | 피싱 | CASE_A_HIGH | 17/92 | 0.9989 | 탐지 |
| 1.0 → 2.0 | https://whatsapp.123zoeken.be/ | 피싱 | CASE_A_HIGH | 17/92 | 0.9084 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-fransik-biz-pravdok-kelmor.pages.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.9946 | 탐지 |
| 1.0 → 2.0 | https://qjozvnvk6bohnpfx5m6.8d8yd9prtx649bohfe2jy7hiu.workers.dev/q/dxbAALy9C75y5TC0yk0ArQyG8uCdV8Q5V0xWZzpJ | 피싱 | CASE_A_HIGH | 14/92 | 0.9049 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-frelor-biz-zormik-kansel.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9887 | 탐지 |
| 1.0 → 2.0 | http://xfinitylogininc.weebly.com/ | 피싱 | CASE_A_HIGH | 16/92 | 0.9824 | 탐지 |
| 1.0 → 2.0 | http://safe-ldge-r-live.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9615 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-kavsor-biz-londik-pramel.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9888 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-zelrek-biz-karsik-vandom.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.992 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-fravik-biz-holdor-prensak.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9882 | 탐지 |
| 1.0 → 2.0 | https://web-fun-checkout-prototype-uniswap.vercel.app/launches | 피싱 | CASE_A_HIGH | 18/92 | 0.7812 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-kersel-biz-vondok-zarmik.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9824 | 탐지 |
| 1.0 → 2.0 | http://newmidas.gamerstored.com/ | 피싱 | CASE_A_HIGH | 19/92 | 0.8215 | 탐지 |
| 1.0 → 2.0 | https://sp12ct-londor-biz-hazrek-framel.pages.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.9912 | 탐지 |
| 1.0 → 2.0 | http://wow.3dgbbfu8gk.com/ | 피싱 | CASE_A_HIGH | 16/92 | 0.9361 | 탐지 |
| 1.0 → 2.0 | https://testamentenligne.info/Q0g0MS1OMTUxNS1EMDkwNjA2 | 피싱 | CASE_A_HIGH | 26/92 | 0.5815 | 탐지 |
| 1.0 → 2.0 | https://www.roblox.com.mu/users/1081301329/profile | 피싱 | CASE_A_HIGH | 23/92 | 0.744 | 탐지 |
| 1.0 → 2.0 | http://portal-io-start-docs.typedream.app/ | 피싱 | CASE_A_HIGH | 18/92 | 0.9556 | 탐지 |
| 1.0 → 2.0 | https://bybit-referral-code-id.vercel.app/ | 피싱 | CASE_A_HIGH | 14/92 | 0.946 | 탐지 |
| 1.0 → 2.0 | https://sp13ct-prandel-biz-zormek-lavkor.pages.dev/ | 피싱 | CASE_A_HIGH | 15/92 | 0.9908 | 탐지 |
| 1.0 → 2.0 | https://web-fun-checkout-prototype-uniswap.vercel.app/explore | 피싱 | CASE_A_HIGH | 18/92 | 0.7989 | 탐지 |
| 1.0 → 2.0 | https://facebooklogin8989.blogspot.com/ | 피싱 | CASE_A_HIGH | 15/92 | 0.9741 | 탐지 |
| 1.0 → 2.0 | http://www.docs-google.com/?urid=gzxpuIVeWdNiUXIxrbheaFg821tlE7QFW203x-oN08gfw89lnIlV7YBaCkZeUXTCdbLg-zBixdoNVc60bAI897zbKBJTQrLwFegyd5AqhHIh_-GkVCrmPQOhgGYjrUUkixXg6nAbwXVGYsYrqqqe | 피싱 | CASE_A_HIGH | 17/92 | 0.9562 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-kavmik-biz-zondor-lersak.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9888 | 탐지 |
| 1.0 → 2.0 | https://wesmongtx.4663.org/ | 피싱 | CASE_A_HIGH | 14/92 | 0.9755 | 탐지 |
| 1.0 → 2.0 | http://seasharebox648-e4a23cdf77d2.herokuapp.com/ | 피싱 | CASE_A_HIGH | 15/92 | 0.9938 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-keldik-biz-zamrok-horsel.pages.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.9888 | 탐지 |
| 1.0 → 2.0 | http://instagram-instagram.blogspot.com/ | 피싱 | CASE_A_HIGH | 16/92 | 0.8976 | 탐지 |
| 1.0 → 2.0 | http://comprehensive-employee-143296.framer.app/ | 피싱 | CASE_A_HIGH | 20/92 | 0.998 | 탐지 |
| 1.0 → 2.0 | https://originalinstagram.blogspot.com/?m=1 | 피싱 | CASE_A_HIGH | 18/92 | 0.7556 | 탐지 |
| 1.0 → 2.0 | https://rooooo22.netlify.app/ | 피싱 | CASE_A_HIGH | 18/92 | 0.9036 | 탐지 |
| 1.0 → 2.0 | http://webpages-trzor-suite.typedream.app/ | 피싱 | CASE_A_HIGH | 16/92 | 0.9214 | 탐지 |
| 1.0 → 2.0 | http://liveledger-offical.pages.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.8962 | 탐지 |
| 1.0 → 2.0 | https://3.therewardinglocker.com/ | 피싱 | CASE_A_HIGH | 19/92 | 0.9388 | 탐지 |
| 1.0 → 2.0 | http://trustworthy-shallot-648391.framer.app/ | 피싱 | CASE_A_HIGH | 19/92 | 0.9992 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-vordel-biz-fravsel-kamrik.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.995 | 탐지 |
| 1.0 → 2.0 | http://7.rewardingmyself.com/ | 피싱 | CASE_A_HIGH | 19/92 | 0.9308 | 탐지 |
| 1.0 → 2.0 | http://2fd86-j7ic3-7s49z5-jkffss.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.999 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-kendor-biz-frondik-zalvek.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9917 | 탐지 |
| 1.0 → 2.0 | http://eisha001.github.io/Netflix | 피싱 | CASE_A_HIGH | 21/92 | 0.9056 | 탐지 |
| 1.0 → 2.0 | http://anshuman-bharti-79.github.io/amazon-clone | 피싱 | CASE_A_HIGH | 20/92 | 0.9833 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-handor-biz-prasvik-frelok.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9916 | 탐지 |
| 1.0 → 2.0 | https://sp12ct-lavsel-biz-hormek-frandik.pages.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.9905 | 탐지 |
| 1.0 → 2.0 | https://sp12ct-lavdor-biz-pravsel-hondik.pages.dev/ | 피싱 | CASE_A_HIGH | 15/92 | 0.9908 | 탐지 |
| 1.0 → 2.0 | https://qerwrrsfwetrans.edgeone.dev/?email=a.b@c | 피싱 | CASE_A_HIGH | 21/92 | 0.9902 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-varsik-biz-zemdok-kolmar.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.992 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-vormek-biz-pransik-keldor.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9917 | 탐지 |
| 1.0 → 2.0 | https://web-fun-checkout-prototype-uniswap.vercel.app/swap | 피싱 | CASE_A_HIGH | 18/92 | 0.8081 | 탐지 |
| 1.0 → 2.0 | https://opensea-sessions56.netlify.app/ | 피싱 | CASE_A_HIGH | 19/92 | 0.9831 | 탐지 |
| 1.0 → 2.0 | http://e8a5dd-98jv-sbu49-jb48i-ezmw.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9957 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-holdik-biz-fransel-pravrok.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9945 | 탐지 |
| 1.0 → 2.0 | http://www.acessopessoafisica.cc/ | 피싱 | CASE_A_HIGH | 19/92 | 0.9041 | 탐지 |
| 1.0 → 2.0 | http://facebookloginsignub.blogspot.com/ | 피싱 | CASE_A_HIGH | 21/92 | 0.9448 | 탐지 |
| 1.0 → 2.0 | https://cn-imtoken.tronscoin.com/ | 피싱 | CASE_A_HIGH | 22/92 | 0.7639 | 탐지 |
| 1.0 → 2.0 | http://jzkvm819m-tqbrp341k-3a1e-xwl59p.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9977 | 탐지 |
| 1.0 → 2.0 | https://www.roblox.com.mu/users/8256586766/profile | 피싱 | CASE_A_HIGH | 23/92 | 0.744 | 탐지 |
| 1.0 → 2.0 | https://sp13ct-vormel-biz-pradik-kersor.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9869 | 탐지 |
| 1.0 → 2.0 | http://sucurpanamigoc360.fly.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.9671 | 탐지 |
| 1.0 → 2.0 | http://www.facebook-hack-login.blogspot.com/ | 피싱 | CASE_A_HIGH | 19/92 | 0.782 | 탐지 |
| 1.0 → 2.0 | https://social2.vulidity.de/vuliscope/876d71ac-a664-4480-bf91-348d415286ae/hosting/07982858-4f3f-4e9d-bf31-477a2bc2c7df/index.html | 피싱 | CASE_A_HIGH | 17/92 | 0.7453 | 탐지 |
| 1.0 → 2.0 | http://32pm38-usb-euw67i-cc2kt-skicc.pages.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.9978 | 탐지 |
| 1.0 → 2.0 | https://web-fun-checkout-prototype-uniswap.vercel.app/portfolio | 피싱 | CASE_A_HIGH | 18/92 | 0.7895 | 탐지 |
| 1.0 → 2.0 | http://xfinity-comcasts.github.io/xfinity-flask | 피싱 | CASE_A_HIGH | 17/92 | 0.9374 | 탐지 |
| 1.0 → 2.0 | https://cheery-parfait-c54a7b.netlify.app/ | 피싱 | CASE_A_HIGH | 16/92 | 0.9842 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-hazdok-biz-frandel-vormik.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9915 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-frasel-biz-zondik-pravlor.pages.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.9883 | 탐지 |
| 1.0 → 2.0 | http://sp12ct-pravsel-biz-hazrok-zendor.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9917 | 탐지 |
| 1.0 → 2.0 | http://webxfinitylogin.weebly.com/ | 피싱 | CASE_A_HIGH | 16/92 | 0.9854 | 탐지 |
| 1.0 → 2.0 | http://aware-research-270929.framer.app/ | 피싱 | CASE_A_HIGH | 19/92 | 0.9984 | 탐지 |
| 1.0 → 2.0 | http://ml-facebook.blogspot.com/ | 피싱 | CASE_A_HIGH | 19/92 | 0.8984 | 탐지 |
| 1.0 → 2.0 | https://ledger-live-login-cryptos.pages.dev/ | 피싱 | CASE_A_HIGH | 20/92 | 0.9878 | 탐지 |
| 1.0 → 2.0 | https://celadon-stroopwafel-407584.netlify.app/ | 피싱 | CASE_A_HIGH | 18/92 | 0.9958 | 탐지 |
| 1.0 → 2.0 | https://sp12ct-lordik-biz-prandel-hensor.pages.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.9945 | 탐지 |
| 1.0 → 2.0 | https://im-token.tronscoin.com/ | 피싱 | CASE_A_HIGH | 21/92 | 0.884 | 탐지 |
| 1.0 → 2.0 | https://www.app81-facebook.blogspot.com/ | 피싱 | CASE_A_HIGH | 20/92 | 0.5074 | 탐지 |
| 1.0 → 2.0 | http://opensea-ioget.netlify.app/ | 피싱 | CASE_A_HIGH | 16/92 | 0.8728 | 탐지 |
| 1.0 → 2.0 | https://7.rewardingmyself.com/index-form.php | 피싱 | CASE_A_HIGH | 17/92 | 0.7535 | 탐지 |
| 1.0 → 2.0 | https://binance-register.blogspot.com/ | 피싱 | CASE_A_HIGH | 16/92 | 0.9205 | 탐지 |
| 1.0 → 2.0 | https://5-9-7-0-0.bioprodeintal.workers.dev/ | 피싱 | CASE_A_HIGH | 14/92 | 0.9944 | 탐지 |
| 1.0 → 2.0 | http://www.2-euroline.com/ | 피싱 | CASE_A_HIGH | 16/92 | 0.9129 | 탐지 |
| 1.0 → 2.0 | http://xlbdw2a16vs-ycgfnmja-8d3e2f-xlq54c.pages.dev/ | 피싱 | CASE_A_HIGH | 13/92 | 0.9899 | 탐지 |
| 2.0 → 3.0 | http://sp12ct-zardok-biz-hensel-fravik.pages.dev/ | 피싱 | CASE_A_HIGH | 12/92 | 0.9887 | 탐지 |
| 2.0 → 3.0 | http://claimgethererblxslimited.blogspot.com/ | 피싱 | CASE_A_HIGH | 12/92 | 0.8255 | 탐지 |
| 2.0 → 3.0 | http://www.comcastmailupdateaccount.weebly.com/ | 피싱 | CASE_A_HIGH | 15/92 | 0.4549 | 탐지 |
| 2.0 → 3.0 | https://www.4sesor14d3cuenta.webcindario.com/ | 피싱 | CASE_A_HIGH | 19/92 | 0.5171 | 탐지 |
| 2.0 → 3.0 | https://kxztp5c80sk-mvrqlwur-9e4f1c-zd611a.pages.dev/ | 피싱 | CASE_A_HIGH | 9/92 | 0.9867 | 탐지 |
| 2.0 → 3.0 | https://hotmailskjfhurytnadinbox.weebly.com/ | 피싱 | CASE_A_HIGH | 13/92 | 0.8077 | 탐지 |
| 2.0 → 3.0 | http://www.kukcon-xlognx.godaddysites.com/ | 피싱 | CASE_A_HIGH | 17/92 | 0.3731 | 탐지 |
| 2.0 → 3.0 | https://zeexpresss-delivery.shop/ | 피싱 | CASE_A_HIGH | 14/92 | 0.6997 | 탐지 |
| 2.0 → 3.0 | http://7.therewardinglocker.com/index-form.php | 피싱 | CASE_A_HIGH | 17/92 | 0.5007 | 탐지 |
| 2.0 → 3.0 | https://sp13ct-lavkor-biz-prandor-zersik.pages.dev/ | 피싱 | CASE_A_HIGH | 9/92 | 0.9943 | 탐지 |
| 2.0 → 3.0 | http://download-offical-trexrsuite.pages.dev/ | 피싱 | CASE_A_HIGH | 11/92 | 0.9751 | 탐지 |
| 2.0 → 3.0 | https://mail-spectrum-net-login.framer.website/ | 피싱 | CASE_A_HIGH | 9/92 | 0.9717 | 탐지 |
| 2.0 → 3.0 | https://cutt.ly/socsecsgsvc | 피싱 | CASE_A_HIGH | 10/92 | 0.9564 | 탐지 |
| 2.0 → 3.0 | http://mjsihsxi.us.cc/5g/home.html | 피싱 | CASE_A_HIGH | 17/92 | 0.2413 | 탐지 |
| 2.0 → 3.0 | http://rebrand.ly/g59jl7z | 피싱 | CASE_A_HIGH | 14/92 | 0.8182 | 탐지 |
| 2.0 → 3.0 | https://morlena-nqx-belqumi-c7x3hq98.pages.dev/ | 피싱 | CASE_A_HIGH | 10/92 | 0.9922 | 탐지 |
| 2.0 → 3.0 | http://www.instagramaccounthacks.blogspot.com/ | 피싱 | CASE_A_HIGH | 17/92 | 0.4225 | 탐지 |
| 2.0 → 3.0 | https://sarangventures.in/747534757 | 피싱 | CASE_A_HIGH | 16/92 | 0.5547 | 탐지 |
| 2.0 → 3.0 | https://mackeyins.com/xn/link/dd/Alibaba/index.php | 피싱 | CASE_A_HIGH | 21/92 | 0.2712 | 탐지 |
| 2.0 → 3.0 | http://face-book-book.blogspot.com/2014/04/function-envflushafunction-bcforvar-d.html | 피싱 | CASE_A_HIGH | 20/92 | 0.0007 | 탐지 |
| 2.0 → 3.0 | https://deepakkrmandal18-netizen.github.io/Instagramweb | 피싱 | CASE_A_HIGH | 9/92 | 0.9699 | 탐지 |
| 2.0 → 3.0 | https://vinayakkubati818-del.github.io/Netflix-Clone | 피싱 | CASE_A_HIGH | 10/92 | 0.9666 | 탐지 |
| 2.0 → 3.0 | https://www.facebooklogin8989.blogspot.com/ | 피싱 | CASE_A_HIGH | 16/92 | 0.6819 | 탐지 |
| 2.0 → 3.0 | https://sp13ct-vormor-biz-fradik-kazsel.pages.dev/send_appeal_request | 피싱 | CASE_A_HIGH | 12/92 | 0.9708 | 탐지 |
| 2.0 → 3.0 | https://worldwideexpressdeliveryfedx.github.io/fedx | 피싱 | CASE_A_HIGH | 14/92 | 0.7048 | 탐지 |
| 2.0 → 3.0 | http://virtualnextpartner.com/ | 피싱 | CASE_A_HIGH | 20/92 | 0.0335 | 탐지 |
| 2.0 → 3.0 | https://sucurpanamigoc360.fly.dev/espejo/landing.html | 피싱 | CASE_A_HIGH | 14/92 | 0.5956 | 탐지 |
| 2.0 → 3.0 | http://almax.net.br/febukk-mk-place-43556654435 | 피싱 | CASE_A_HIGH | 20/92 | 0.4657 | 탐지 |
| 2.0 → 3.0 | http://moondoteth.github.io/oauthcomcast | 피싱 | CASE_A_HIGH | 20/92 | 0.4287 | 탐지 |
| 2.0 → 3.0 | https://cuttizum.click/s/gRtRb8 | 피싱 | CASE_A_HIGH | 16/92 | 0.6322 | 탐지 |
| 2.0 → 3.0 | http://qwayinternational.in/kkiulj | 피싱 | CASE_A_HIGH | 15/92 | 0.778 | 탐지 |
| 2.0 → 3.0 | http://wqdegnhwas.on-forge.com/ | 피싱 | CASE_A_HIGH | 12/92 | 0.7676 | 탐지 |
| 2.0 → 3.0 | https://vnzkt523mjw-msprqrel-6b5d2e-hb611a.pages.dev/ | 피싱 | CASE_A_HIGH | 9/92 | 0.9867 | 탐지 |
| 2.0 → 3.0 | http://www.anoopsamazon.vercel.app/ | 피싱 | CASE_A_HIGH | 17/92 | 0.2672 | 탐지 |
| 2.0 → 3.0 | https://hbkpt42lkww-xlbdwwur-2b5f7a-hbk94p.pages.dev/ | 피싱 | CASE_A_HIGH | 9/92 | 0.9866 | 탐지 |
| 2.0 → 3.0 | https://snifferip.com/2oV3e.gif | 피싱 | CASE_A_HIGH | 18/92 | 0.1729 | 탐지 |
| 2.0 → 3.0 | https://maheer466.github.io/Netflix-clone | 피싱 | CASE_A_HIGH | 11/92 | 0.9403 | 탐지 |
| 2.0 → 3.0 | https://www.instagram-instagram.blogspot.com/ | 피싱 | CASE_A_HIGH | 17/92 | 0.3387 | 탐지 |
| 2.0 → 3.0 | http://alizamuhammadali010.github.io/Netflix.clone | 피싱 | CASE_A_HIGH | 16/92 | 0.6866 | 탐지 |
| 2.0 → 3.0 | https://rbcode.net/v/6780d346df48e6fb4db3cfe1ef9f9092 | 피싱 | CASE_A_HIGH | 23/92 | 0.175 | 탐지 |
| 2.0 → 3.0 | https://pixelquest-btg.pages.dev/ | 피싱 | CASE_A_HIGH | 10/92 | 0.8913 | 탐지 |
| 2.0 → 3.0 | http://educanal.com.py/feisbuk-32454654456 | 피싱 | CASE_A_HIGH | 18/92 | 0.418 | 탐지 |
| 2.0 → 3.0 | http://fix.allwalletdapp.com/ | 피싱 | CASE_A_HIGH | 15/92 | 0.7792 | 탐지 |
| 2.0 → 3.0 | https://onbit.pro/Nikepro.link | 피싱 | CASE_A_HIGH | 19/92 | 0.1571 | 탐지 |
| 2.0 → 3.0 | https://fizafatima24.github.io/Aamazon | 피싱 | CASE_A_HIGH | 12/92 | 0.9278 | 탐지 |
| 2.0 → 3.0 | http://salleryonlnejbhomesiiite.net/ | 피싱 | CASE_A_HIGH | 20/92 | 0.0664 | 탐지 |
| 2.0 → 3.0 | http://mehrazhowlader.github.io/project_test | 피싱 | CASE_A_HIGH | 21/92 | 0.1312 | 탐지 |
| 2.0 → 3.0 | https://s.team-p.my/p/quei-odxi/lrjzqohi | 피싱 | CASE_A_HIGH | 24/92 | 0.2145 | 탐지 |
| 2.0 → 3.0 | https://faq-ledger-live-download.pages.dev/ | 피싱 | CASE_A_HIGH | 10/92 | 0.9359 | 탐지 |
| 2.0 → 3.0 | https://rngkuqoo.elementor.cloud/EN34FJHG7ND53/EN33UY645/M0002X1/info.html | 피싱 | CASE_A_HIGH | 19/92 | 0.0567 | 탐지 |
| 2.0 → 3.0 | https://www.netflix-clone-gilt-phi.vercel.app/ | 피싱 | CASE_A_HIGH | 18/92 | 0.5348 | 탐지 |
| 2.0 → 3.0 | https://tusharkumar80023-create.github.io/Instagram- | 피싱 | CASE_A_HIGH | 9/92 | 0.9883 | 탐지 |
| 2.0 → 3.0 | https://zeexpresss-bebidas.shop/ | 피싱 | CASE_A_HIGH | 18/92 | 0.4883 | 탐지 |
| 2.0 → 3.0 | https://amandiwakarrr.github.io/Netflix-Clone | 피싱 | CASE_A_HIGH | 14/92 | 0.63 | 탐지 |
| 2.0 → 3.0 | https://wvwv-roblox.co/users/1191536658/profile | 피싱 | CASE_A_HIGH | 18/92 | 0.0746 | 탐지 |
| 2.0 → 3.0 | http://a3b9c102.com/register.html | 피싱 | CASE_A_HIGH | 18/92 | 0.0665 | 탐지 |
| 2.0 → 3.0 | https://mirzohidshermanov36-hub.github.io/Instagram.com | 피싱 | CASE_A_HIGH | 14/92 | 0.8602 | 탐지 |
| 2.0 → 3.0 | http://xlbdw1b41dr-hbkptpli-8a9b6f-xlq85c.pages.dev/ | 피싱 | CASE_A_HIGH | 9/92 | 0.9899 | 탐지 |
| 2.0 → 3.0 | http://shekashish.github.io/netflix_clone | 피싱 | CASE_A_HIGH | 17/92 | 0.1602 | 탐지 |
| 2.0 → 3.0 | http://reactivarwhats.webcindario.com/index.html | 피싱 | CASE_A_HIGH | 17/92 | 0.508 | 탐지 |
| 2.0 → 3.0 | http://galyabet.app/ | 피싱 | CASE_A_HIGH | 20/92 | 0.2103 | 탐지 |
| 2.0 → 3.0 | http://performance-door.net/rakuten/signjp | 피싱 | CASE_A_HIGH | 19/92 | 0.1053 | 탐지 |
| 2.0 → 3.0 | https://xyce-ld.nefxed.biz.id/jmk/int.html | 피싱 | CASE_A_HIGH | 14/92 | 0.5273 | 탐지 |
| 2.0 → 3.0 | https://fragrant-tooth-899d.nklsrqgiosckuev.workers.dev/meta.help | 피싱 | CASE_A_HIGH | 10/92 | 0.9717 | 탐지 |
| 2.0 → 3.0 | https://24h-zedelivery.site/ | 피싱 | CASE_A_HIGH | 13/92 | 0.8483 | 탐지 |
| 2.0 → 3.0 | https://qrco.de/bgxR5S | 피싱 | CASE_A_HIGH | 12/92 | 0.9996 | 탐지 |
| 2.0 → 3.0 | http://myaol-serv.cwrdl.workers.dev/ | 피싱 | CASE_A_HIGH | 16/92 | 0.5719 | 탐지 |
| 2.0 → 3.0 | http://azalmandhai03-ctrl.github.io/NETFLIX-.-CLONE-ASSIGNMENT | 피싱 | CASE_A_HIGH | 18/92 | 0.4099 | 탐지 |
| 2.0 → 3.0 | https://www.cambrianschoolbd.com/mail | 피싱 | CASE_A_HIGH | 15/92 | 0.6146 | 탐지 |
| 2.0 → 3.0 | https://destructor82.github.io/legger-v2 | 피싱 | CASE_A_HIGH | 12/92 | 0.9755 | 탐지 |
| 3.0 → 3.5 | https://big.as/Mail | 피싱 | CASE_A_HIGH | 15/92 | 0.2029 | 탐지 |
| 3.0 → 3.5 | https://wvwv-roblox.co/users/909139181/profile) | 피싱 | CASE_A_HIGH | 17/92 | 0.0154 | 탐지 |
| 3.0 → 3.5 | https://iqraamir22.github.io/Netflix-clone | 피싱 | CASE_A_HIGH | 8/92 | 0.9506 | 탐지 |
| 3.0 → 3.5 | https://n-ux539.github.io/FDL2604C02 | 피싱 | CASE_A_HIGH | 8/92 | 0.9894 | 탐지 |
| 3.0 → 3.5 | https://mydropsboxmaill.weebly.com/ | 피싱 | CASE_A_HIGH | 10/92 | 0.6858 | 탐지 |
| 3.0 → 3.5 | http://www.71713.xyz/ | 피싱 | CASE_A_HIGH | 12/92 | 0.5954 | 탐지 |
| 3.0 → 3.5 | https://sunniacademy.org/docsign/page.html?sid=1L9mSwQk4YpXjzNx6QmAbGi9zV2kbyfPjGrlztviQAY5XqPCqgVd2pK8f2neWYOmKZoe8VddIY2J7M9nMh7fQuFgniTdb1KmqDRdD36Lc7ue7oKtdY6VzEZtVNI | 피싱 | CASE_A_HIGH | 12/92 | 0.5771 | 탐지 |
| 3.0 → 3.5 | http://www.fix.allwalletdapp.com/ | 피싱 | CASE_A_HIGH | 14/92 | 0.3149 | 탐지 |
| 3.0 → 3.5 | https://mirzohidshermanov36-hub.github.io/Instagram-relss | 피싱 | CASE_A_HIGH | 10/92 | 0.759 | 탐지 |
| 3.0 → 3.5 | https://ep-ch-op3izuems2p7-cmdsg8byeda5d9g3.z02.azurefd.net/ | 피싱 | CASE_A_HIGH | 8/92 | 0.9853 | 탐지 |
| 3.0 → 3.5 | https://confirmationofmailupdate.weeblysite.com/ | 피싱 | CASE_A_HIGH | 8/92 | 0.913 | 탐지 |
| 3.0 → 3.5 | https://sin1.contabostorage.com/d96fc17aeb3741e493b2e5b3a72a669f:truyoioit/billsslogin.html | 피싱 | CASE_A_HIGH | 16/92 | 0.0838 | 탐지 |
| 3.0 → 3.5 | https://exodswalet.pages.dev/]Exodus | 피싱 | CASE_A_HIGH | 13/92 | 0.511 | 탐지 |
| 3.0 → 3.5 | https://8ruuxo-pit64-xglds-vwh-m0lscg.pages.dev/qaz-wsx-edc-rfv | 피싱 | CASE_A_HIGH | 8/92 | 0.9601 | 탐지 |
| 3.5 → 4.0 | http://social-statements.com/esign.social-statements.com | 피싱 | CASE_A_HIGH | 15/92 | 0.0662 | 탐지 |
| 3.5 → 4.0 | https://hidden-scene-8d69.rvxejgblnuevhsi.workers.dev/account-center | 피싱 | CASE_A_HIGH | 7/92 | 0.9477 | 탐지 |
| 3.5 → 4.0 | https://71698.xyz/ | 피싱 | CASE_A_HIGH | 13/92 | 0.1642 | 탐지 |
| 3.5 → 4.0 | https://m.tyc643.com/ | 피싱 | CASE_A_HIGH | 12/92 | 0.3283 | 탐지 |
| 3.5 → 4.0 | https://skg019403.github.io/New-1 | 피싱 | CASE_A_HIGH | 7/92 | 0.991 | 탐지 |
| 3.5 → 4.0 | https://paribcardsegr.bond/ | 피싱 | CASE_A_HIGH | 15/92 | 0.0817 | 탐지 |
| 3.5 → 4.0 | http://www.y99s.xyz/ | 피싱 | CASE_A_HIGH | 12/92 | 0.349 | 탐지 |
| 3.5 → 4.0 | https://social-statements.com/esign.social-statements.com | 피싱 | CASE_A_HIGH | 14/92 | 0.0828 | 탐지 |
| 3.5 → 4.0 | https://instgrammail33-gif.github.io/instagram | 피싱 | CASE_A_HIGH | 7/92 | 0.9909 | 탐지 |
| 3.5 → 4.0 | https://resbonsibale1.pages.dev/public | 피싱 | CASE_A_HIGH | 7/92 | 0.8966 | 탐지 |
| 3.5 → 4.0 | http://yt2mp3api.ofismall.az/ProcessValidation/view-pr-do/plugin-read-mail/d20xODcybTU3MA**/attach-viewer-main | 피싱 | CASE_A_HIGH | 15/92 | 0.0151 | 탐지 |
| 3.5 → 4.0 | http://yt2mp3api.ofismall.az/ProcessValidation/view-pr-do/plugin-read-mail/d20xODcybTU3MA**/attach-viewer-main/aW5mb0BncnVlbmF1ZXJob2YuYXQ | 피싱 | CASE_A_HIGH | 15/92 | 0.0184 | 탐지 |
| 3.5 → 4.0 | https://neopixellightsaber.co/wp-includes/wps/soge | 피싱 | CASE_A_HIGH | 13/92 | 0.1205 | 탐지 |
| 4.0 → 4.5 | https://instgrammail33-gif.github.io/instagram/d.html | 피싱 | CASE_A_HIGH | 8/92 | 0.6295 | 탐지 |
| 4.0 → 4.5 | http://dhlvarese.it/index.html | 피싱 | CASE_A_HIGH | 12/92 | 0.1655 | 탐지 |
| 4.0 → 4.5 | https://facebooklogin1now.blogspot.com/?m=1 | 피싱 | CASE_A_HIGH | 6/92 | 0.9732 | 탐지 |
| 4.0 → 4.5 | https://cool-sound-9e44.jessiedunlapgof21787yad94624.workers.dev/support-index | 피싱 | CASE_A_HIGH | 6/92 | 0.9959 | 탐지 |
| 4.0 → 4.5 | https://late-lab-7d38.aipsfxywsiqmxmt.workers.dev/meta.help | 피싱 | CASE_A_HIGH | 6/92 | 0.9737 | 탐지 |
| 4.0 → 4.5 | https://frosty-frog-6b2e.egfyolgvnwainsw.workers.dev/meta.help | 피싱 | CASE_A_HIGH | 6/92 | 0.9769 | 탐지 |
| 4.5 → 5.0 | https://optinfs.optimalinfos.com/pbfr | 피싱 | CASE_A_HIGH | 8/92 | 0.5506 | 탐지 |
| 4.5 → 5.0 | https://www.vkr.sqs.mybluehost.me/EN/TD-ZE5KIzX0UW4&oauth_key_signature=eyJraWQOiJrUFVqdlNhT25GWUVDakpjMmV1MXJvNGxnb2VFeXJJb2tCbU1X3BiZXN/app.php | 피싱 | CASE_A_HIGH | 11/92 | 0.1241 | 탐지 |
| 5.0 → 6.0 | https://u.to/roblox-com-users-1081301329-profile/ocSkIg | 피싱 | CASE_A_HIGH | 9/92 | 0.1153 | 탐지 |
| 5.0 → 6.0 | https://azalmandhai03-ctrl.github.io/NETFLIX-.-CLONE-ASSIGNMENT | 피싱 | CASE_A_HIGH | 8/92 | 0.4702 | 탐지 |
| 5.0 → 6.0 | https://facebooktrade.com/instagram.html | 피싱 | CASE_A_HIGH | 10/92 | 0.0427 | 탐지 |
| 5.0 → 6.0 | https://instagram-demo.blogspot.com/ | 피싱 | CASE_A_HIGH | 5/92 | 0.8456 | 탐지 |
| 5.0 → 6.0 | https://alizamuhammadali010.github.io/Netflix.clone | 피싱 | CASE_A_HIGH | 6/92 | 0.7271 | 탐지 |
| 5.0 → 6.0 | https://www.vkr.sqs.mybluehost.me/EN/TD-ZE5KIzX0UW4&oauth_key_signature=eyJraWQOiJrUFVqdlNhT25GWUVDakpjMmV1MXJvNGxnb2VFeXJJb2tCbU1X3BiZXN/loading.php | 피싱 | CASE_A_HIGH | 9/92 | 0.1369 | 탐지 |
| 6.0 → 8.0 | http://whatsapp-tools.lateinos.com.br/ | 피싱 | CASE_A_HIGH | 7/92 | 0.3272 | 탐지 |
| 10.0 → 12.0 | https://vk.ru | 정상 | CASE_A_LOW | 1/92 | 0.7706 | 탐지(오탐) |
| 10.0 → 12.0 | https://wa.me | 정상 | CASE_A_LOW | 1/92 | 0.7709 | 탐지(오탐) |
| 20.0 → 25.0 | https://qq.com | 정상 | CASE_A_LOW | 1/92 | 0.6511 | 탐지(오탐) |

## 2. τL 확장 격자 (최종점, 다른 파라미터 고정)

| τL | 격자 | Recall | Precision | F1 | FPR | BLOCKED R / FPR | 미등재 15건 | C p* (τL/0.8) | SUSPICIOUS 폭 (τH−τL) | B 재설계 가능 W | 절차 일관 F1 / FPR / 15건 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0.25 | 원 격자 | 98.4 | 63.08 | 76.88 | 57.6 | 96.4 / 0.8 | 12/15 | 0.3125 | 0.4 | 없음 | — |
| 0.3 | 원 격자 | 98.4 | 83.96 | 90.61 | 18.8 | 96.4 / 0.8 | 12/15 | 0.375 | 0.35 | 없음 | — |
| 0.35 | 원 격자 | 98.4 | 86.62 | 92.13 | 15.2 | 96.4 / 0.8 | 12/15 | 0.4375 | 0.3 | 0.4 | 94.25 / 10.4 / 12 |
| 0.4 | 원 격자 | 98.0 | 90.74 | 94.23 | 10.0 | 96.4 / 0.8 | 11/15 | 0.5 | 0.25 | 0.45 | 94.96 / 8.4 / 11 |
| 0.45 | 원 격자 | 98.0 | 93.16 | 95.52 | 7.2 | 96.4 / 0.8 | 11/15 | 0.5625 | 0.2 | 0.5 | 95.52 / 7.2 / 11 |
| 0.5 | 확장 | 98.0 | 95.33 | 96.65 | 4.8 | 96.4 / 0.8 | 11/15 | 0.625 | 0.15 | 0.55 | 96.27 / 5.6 / 11 |
| 0.55 | 확장 | 97.6 | 95.69 | 96.63 | 4.4 | 96.4 / 0.8 | 10/15 | 0.6875 | 0.1 | 0.6 | 96.44 / 4.8 / 10 |
| 0.6 | 확장 | 96.4 | 98.77 | 97.57 | 1.2 | 96.4 / 0.8 | 7/15 | 0.75 | 0.05 | 0.7 | 96.79 / 2.8 / 7 |
| 0.64 | 확장 | 96.4 | 99.18 | 97.77 | 0.8 | 96.4 / 0.8 | 7/15 | 0.8 | 0.01 | 0.7 | 97.57 / 1.2 / 7 |

## 3. W_ML(A_HIGH) — Override 유무별 BLOCKED Recall

| W_ML(A_HIGH) | d≥5 최소 점수 (p_ML=0) | 항상 BLOCKED (≥ τH 0.65) | BLOCKED Recall (Override 켬) | BLOCKED Recall (Override 끔) | F1 | FPR |
|---|---|---|---|---|---|---|
| 0.1 | 0.9 | 예 | 96.4 | 96.4 | 95.52 | 7.2 |
| 0.15 | 0.85 | 예 | 96.4 | 96.4 | 95.52 | 7.2 |
| 0.2 | 0.8 | 예 | 96.4 | 96.4 | 95.52 | 7.2 |
| 0.25 | 0.75 | 예 | 96.4 | 96.4 | 95.52 | 7.2 |
| 0.3 | 0.7 | 예 | 96.4 | 96.4 | 95.52 | 7.2 |
| 0.35 | 0.65 | 예 | 96.4 | 96.4 | 95.52 | 7.2 |
| 0.4 | 0.6 | 아니오 | 96.4 | 89.2 | 95.52 | 7.2 |
| 0.45 | 0.55 | 아니오 | 96.4 | 84.8 | 95.52 | 7.2 |
| 0.5 | 0.5 | 아니오 | 96.4 | 83.6 | 95.52 | 7.2 |

## 4. 고정 융합(0.5:0.5) 베이스라인 — 검증 집합에서 자체 τL·τH 선정

**α = 18.4** → τL = 0.5 (F1 최대), τH = 0.6 (정상→BLOCKED ≤ 1%, BLOCKED Recall 최대)

| τL | TP | FP | TN | FN | Recall | Precision | F1 | FPR | 미등재 15건 |
|---|---|---|---|---|---|---|---|---|---|
| 0.25 | 245 | 157 | 93 | 5 | 98.0 | 60.95 | 75.15 | 62.8 | 11/15 |
| 0.3 | 245 | 149 | 101 | 5 | 98.0 | 62.18 | 76.09 | 59.6 | 11/15 |
| 0.35 | 244 | 135 | 115 | 6 | 97.6 | 64.38 | 77.58 | 54.0 | 10/15 |
| 0.4 | 241 | 111 | 139 | 9 | 96.4 | 68.47 | 80.07 | 44.4 | 7/15 |
| 0.45 | 239 | 98 | 152 | 11 | 95.6 | 70.92 | 81.43 | 39.2 | 5/15 |
| 0.5 | 234 | 7 | 243 | 16 | 93.6 | 97.1 | 95.32 | 2.8 | 0/15 |
| 0.55 | 220 | 7 | 243 | 30 | 88.0 | 96.92 | 92.24 | 2.8 | 0/15 |
| 0.6 | 208 | 0 | 250 | 42 | 83.2 | 100.0 | 90.83 | 0.0 | 0/15 |
| 0.65 | 202 | 0 | 250 | 48 | 80.8 | 100.0 | 89.38 | 0.0 | 0/15 |

선정 결과: Recall 93.6 / Precision 97.1 / F1 95.32 / FPR 2.8 · BLOCKED Recall 83.2 / 정상→BLOCKED 0.0 · 미등재 15건 0/15
제안(최종) 11/15 vs 고정(자체 τ) 0/15: 제안만 탐지 b = 11, 고정만 탐지 c = 0, 정확 이항검정 p = 0.001
전체 500건 McNemar(제안 vs 고정 자체 τ): {'b': 11, 'c': 11, 'p_value': 1.0, 'method': 'exact-binomial'}

**α = 3.0** → τL = 0.5 (F1 최대), τH = 0.55 (정상→BLOCKED ≤ 1%, BLOCKED Recall 최대)

| τL | TP | FP | TN | FN | Recall | Precision | F1 | FPR | 미등재 15건 |
|---|---|---|---|---|---|---|---|---|---|
| 0.25 | 241 | 153 | 97 | 9 | 96.4 | 61.17 | 74.84 | 61.2 | 11/15 |
| 0.3 | 231 | 145 | 105 | 19 | 92.4 | 61.44 | 73.8 | 58.0 | 11/15 |
| 0.35 | 223 | 132 | 118 | 27 | 89.2 | 62.82 | 73.72 | 52.8 | 10/15 |
| 0.4 | 210 | 110 | 140 | 40 | 84.0 | 65.62 | 73.68 | 44.0 | 7/15 |
| 0.45 | 202 | 96 | 154 | 48 | 80.8 | 67.79 | 73.72 | 38.4 | 5/15 |
| 0.5 | 185 | 7 | 243 | 65 | 74.0 | 96.35 | 83.71 | 2.8 | 0/15 |
| 0.55 | 173 | 0 | 250 | 77 | 69.2 | 100.0 | 81.8 | 0.0 | 0/15 |
| 0.6 | 156 | 0 | 250 | 94 | 62.4 | 100.0 | 76.85 | 0.0 | 0/15 |
| 0.65 | 126 | 0 | 250 | 124 | 50.4 | 100.0 | 67.02 | 0.0 | 0/15 |

선정 결과: Recall 74.0 / Precision 96.35 / F1 83.71 / FPR 2.8 · BLOCKED Recall 69.2 / 정상→BLOCKED 0.0 · 미등재 15건 0/15
제안(최종) 11/15 vs 고정(자체 τ) 0/15: 제안만 탐지 b = 11, 고정만 탐지 c = 0, 정확 이항검정 p = 0.001
전체 500건 McNemar(제안 vs 고정 자체 τ): {'b': 60, 'c': 11, 'p_value': 1.222546450333378e-08, 'method': 'chi2-continuity'}

## 5. VT 단독 행 (Table 5 후보)

| 방법 | TP | FP | TN | FN | Recall | Precision | F1 | FPR | 미등재 15건 |
|---|---|---|---|---|---|---|---|---|---|
| VT only (d ≥ 5) | 234 | 0 | 250 | 16 | 93.6 | 100.0 | 96.69 | 0.0 | 0/15 |
| VT only (d ≥ 1) | 235 | 22 | 228 | 15 | 94.0 | 91.44 | 92.7 | 8.8 | 0/15 |

McNemar 제안 vs VT d≥5: {'b': 11, 'c': 18, 'p_value': 0.26520539259150755, 'method': 'chi2-continuity'}

## 6. 선정 단계 가중치 스윕 (기준점: α=18.4 d≥5 τL=0.35 τH=0.65 W=(0.25/0.5/0.3/0.8) θ=0.3)

**w_a_high** — 1차 값 0.25 F1 94.8 / 격자 최적 0.1 F1 94.8 / 차이 0.0%p → 유지 (R1, < 1.0%p)

| 값 | Recall | Precision | F1 | FPR | BLOCKED R | BLOCKED FPR |
|---|---|---|---|---|---|---|
| 0.1 | 98.4 | 91.45 | 94.8 | 9.2 | 96.4 | 0.8 |
| 0.15 | 98.4 | 91.45 | 94.8 | 9.2 | 96.4 | 0.8 |
| 0.2 | 98.4 | 91.45 | 94.8 | 9.2 | 96.4 | 0.8 |
| 0.25 | 98.4 | 91.45 | 94.8 | 9.2 | 96.4 | 0.8 |
| 0.3 | 98.4 | 91.45 | 94.8 | 9.2 | 96.4 | 0.8 |
| 0.35 | 98.4 | 91.45 | 94.8 | 9.2 | 96.4 | 0.8 |
| 0.4 | 98.4 | 91.45 | 94.8 | 9.2 | 89.2 | 0.8 |
| 0.45 | 98.4 | 91.45 | 94.8 | 9.2 | 84.8 | 0.8 |
| 0.5 | 98.4 | 91.45 | 94.8 | 9.2 | 83.6 | 0.8 |

**w_a_low** — 1차 값 0.5 F1 94.8 / 격자 최적 0.3 F1 95.16 / 차이 0.36%p → 유지 (R1, < 1.0%p)

| 값 | Recall | Precision | F1 | FPR | BLOCKED R | BLOCKED FPR |
|---|---|---|---|---|---|---|
| 0.3 | 98.4 | 92.13 | 95.16 | 8.4 | 96.4 | 0.8 |
| 0.35 | 98.4 | 91.79 | 94.98 | 8.8 | 96.4 | 0.8 |
| 0.4 | 98.4 | 91.79 | 94.98 | 8.8 | 96.4 | 0.8 |
| 0.45 | 98.4 | 91.45 | 94.8 | 9.2 | 96.4 | 0.8 |
| 0.5 | 98.4 | 91.45 | 94.8 | 9.2 | 96.4 | 0.8 |
| 0.55 | 98.4 | 91.11 | 94.62 | 9.6 | 96.4 | 0.8 |
| 0.6 | 98.4 | 91.11 | 94.62 | 9.6 | 96.4 | 3.6 |
| 0.65 | 98.4 | 91.11 | 94.62 | 9.6 | 96.4 | 3.6 |
| 0.7 | 98.4 | 91.11 | 94.62 | 9.6 | 96.4 | 3.6 |

**w_c** — 1차 값 0.8 F1 94.8 / 격자 최적 0.5 F1 95.69 / 차이 0.89%p → 유지 (R1, < 1.0%p)

| 값 | Recall | Precision | F1 | FPR | BLOCKED R | BLOCKED FPR |
|---|---|---|---|---|---|---|
| 0.5 | 97.6 | 93.85 | 95.69 | 6.4 | 93.6 | 0.0 |
| 0.6 | 98.0 | 93.16 | 95.52 | 7.2 | 93.6 | 0.0 |
| 0.7 | 98.0 | 92.45 | 95.15 | 8.0 | 95.6 | 0.0 |
| 0.8 | 98.4 | 91.45 | 94.8 | 9.2 | 96.4 | 0.8 |
| 0.9 | 98.4 | 90.77 | 94.43 | 10.0 | 96.8 | 1.6 |
| 1.0 | 98.4 | 90.77 | 94.43 | 10.0 | 98.0 | 1.6 |

## 7. 1차 심사본 results.json 발췌 (생성 2026-08-09T09:48:36.424772+00:00, n = 500, sweeps = ['design', 'alpha', 'tau_blocked', 'd_high', 'w_ml_B'])

**W_ML(B) 스윕 (1차, SUSPICIOUS 기준)**

| W_ML(B) | Recall | Precision | F1 | FPR | 미등재 Recall |
|---|---|---|---|---|---|
| 0.3 | 94.0 | 92.16 | 93.07 | 8.0 | 80.0 |
| 0.35 | 94.0 | 92.16 | 93.07 | 8.0 | 80.0 |
| 0.4 | 94.0 | 67.72 | 78.73 | 44.8 | 80.0 |
| 0.45 | 94.0 | 65.64 | 77.3 | 49.2 | 80.0 |
| 0.5 | 94.0 | 62.83 | 75.32 | 55.6 | 80.0 |
| 0.55 | 94.0 | 62.17 | 74.84 | 57.2 | 80.0 |
| 0.6 | 94.0 | 61.2 | 74.13 | 59.6 | 80.0 |
| 0.65 | 94.0 | 60.72 | 73.78 | 60.8 | 80.0 |
| 0.7 | 94.0 | 60.57 | 73.67 | 61.2 | 80.0 |
| 0.75 | 94.0 | 60.26 | 73.44 | 62.0 | 80.0 |
| 0.8 | 94.0 | 60.26 | 73.44 | 62.0 | 80.0 |
| 0.85 | 94.0 | 59.8 | 73.09 | 63.2 | 80.0 |
| 0.9 | 94.0 | 59.05 | 72.53 | 65.2 | 80.0 |
| 0.95 | 94.0 | 58.9 | 72.42 | 65.6 | 80.0 |

**τH 스윕 (1차, BLOCKED 기준)**

| τH | Recall | Precision | F1 | FPR | 미등재 Recall |
|---|---|---|---|---|---|
| 0.45 | 81.2 | 93.98 | 87.12 | 5.2 | 73.33 |
| 0.5 | 69.2 | 93.51 | 79.54 | 4.8 | 73.33 |
| 0.55 | 58.0 | 97.32 | 72.68 | 1.6 | 66.67 |
| 0.6 | 33.6 | 96.55 | 49.85 | 1.2 | 46.67 |
| 0.65 | 19.6 | 96.08 | 32.56 | 0.8 | 46.67 |
| 0.7 | 11.6 | 96.67 | 20.71 | 0.4 | 40.0 |
| 0.75 | 3.6 | 100.0 | 6.95 | 0.0 | 26.67 |
| 0.8 | 0.4 | 100.0 | 0.8 | 0.0 | 0.0 |
| 0.85 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
