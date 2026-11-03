# Ferramentas e licenças externas

Este repositório distribui somente implementação própria e fixtures originais. Não incorpora código do REA nem redistribui os binários abaixo. A licença MIT deste projeto não altera licenças ou marcas de terceiros.

| Componente | Origem oficial | Licença upstream / observação |
| --- | --- | --- |
| JADX 1.5.6 | https://github.com/skylot/jadx | Apache-2.0; consulte avisos das dependências incluídas na distribuição |
| Apktool 3.0.3 | https://github.com/iBotPeaches/Apktool | Apache-2.0; verifique arquivos LICENSE/NOTICE da release |
| Eclipse Temurin Java 21 | https://adoptium.net/ e https://github.com/adoptium/temurin21-binaries | GPLv2 com Classpath Exception e avisos adicionais da distribuição |
| Android SDK / aapt2 / d8 | https://developer.android.com/tools | Usados apenas na integração; termos próprios do SDK e de seus componentes |

O instalador baixa JADX e Apktool de releases oficiais, com SHA-256 fixado em fris_reverse/install.py. O JRE é resolvido na API Adoptium e seu checksum verificado e registrado; isso não equivale a um pin imutável da release de Java. Cada instalação mantém install.json e o inventário de arquivos.

Os downloads não aceitam URLs livres fornecidas pelo APK. Os hosts permitidos e redirecionamentos estão sujeitos à política do instalador. O catálogo não cobre Frida, Ghidra, IDA, Hopper, ADB ou ferramentas comerciais. Não há licença para copiar ativos, projetos ou APKs de terceiros só porque podem ser analisados.
