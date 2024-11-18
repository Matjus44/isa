# DNS Monitor

**Autor**: Matúš Janek  
**Login**: 237464  
**Dátum vytvorenia**: 18. november 2024  

## Popis programu

Tento program sa zameriava na monitoring DNS komunikácie, kde sa spracúvajú pakety ktoré majú podporované recordy a triedy ktoré sú následne vypísané do terminálu. V prípade že trieda alebo record nie je podporavný tak sa tento záznam preskočí a jeho informácie sa nikde neukladajú. Program končí vypísaním všetkých pakiet alebo pomocou signal terminátorov v prípade živého zachytávania paketov. Pri živom vysielaní sa počúva na rozrahní *eth0* ale je možnosť aj na interface *any*. Výpis jednotlivých pakiet je v súlade s referenciami v zadaní. Program využíva Makefile na preklad kódu.

### Funkcionalita:
- Zachytávanie DNS paketov v reálnom čase podľa špecifikácie interface alebo pomocou vstupných pcap súborov.
- Výpis zachytených pakiet.
- Podpora výstupu pre doménové mená a ich preklad.
- Implementácia signal terminátorov.

### Rozšírenie:
- Podpora Linux cooked paketov

### Zoznam odovzdaných súborov:
- main.cpp
- utils.cpp/hpp
- terminators.cpp/hpp
- packet_processing.cpp/hpp
- packet_capturing.cpp/hpp
- argument_parser.cpp/hpp
- Makefile
- README.md
- manual.pdf

### Obmedzenia:
- Program vyžaduje administrátorské oprávnenia pre prístup k sieťovým rozhraniam.

**V programe bolo implentované všetko podľa zadania ako aj podľa jednotlivých referencií uvedených v zadaní.**


## Príklad spustenia


```
./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]
```
