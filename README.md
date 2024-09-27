# Monitorování DNS komunikace

**Meno a priezvisko:** Matúš Janek

**Login:** 237464

## Obsah

1. [Úvod](#úvod)
2. [Vstupné argumenty](#Vstupné-argumenty)
3. [Implementácia](#Implementácia)
    - [Štruktúra repozitára](#Štruktúra-repozitára)
    - [Spracovanie vstupných argumentov](#Spracovanie-vstupných-argumentov)
    - [Vytvorenie a spustenie filtru](#Vytvorenie-a-spustenie-filtru)
    - [Výpis zachytených pakiet](#Výpis-zachytených-pakiet)
4. [Ilustrovaná funkcionalita](#Ilustrovaná-funkcionalita)
5. [Testovanie](#Testovanie)
6. [Bibliografia](#Bibliografia)

## Úvod

Táto dokumentácia slúži ako podrobný manuál k projektu `Monitorování DNS komunikace`, ktorý sa zameriava na implementáciu monitorovania DNS komuníkacie. Projekt umožňuje zachytávanie DNS sieťových paketov a ich následujúce spracovanie a písanie na výstup.

Dokumentácia obsahuje technické detaily implementácie, spôsoby použitia aplikácie a jej funkcionalít, ako aj postupy testovania a validácie implementovaných funkcií. Okrem toho sa tu nachádzajú aj informácie o doplnkových funkciách a prípadne zdroje, ktoré boli využité pri vytváraní projektu. Informácie o zadaní projektu viz. [2].

## Vstupné argumenty <a name="Vstupné-argumenty"></a>

Program je spúšťaný z príkazového riadka s nasledujúcimi parametrami:

`./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]`

Význam jednotlivých vstupných argumentov je špecifikovaný v zadaní viz. [2].

Tento program taktiež podporuje `-help` ktorý vypíše nápovedu, tento argument nesmenie byť zadaný s akýmkoľvek iným vstupným argumentom.

## Implementácia <a name="Implementácia"></a>

### Štruktúra repozitára <a name="Štruktúra-repozitára"></a>

Tento program obsahuje súbory `argument_parser.cpp/hpp` v ktorej je implementovaná trieda `Parser`  ktorá obsahuje atribúty zodpovedajúce jednotlivých vstupných argumentom a metódy a ich spracovanie. `packet_capturing.cpp/hpp` obsahuje triedu `Sniffer` ktorá obsahuje metódy na vytvorenie filtra. Súbory `packet_processing.cpp/hpp` obsahuje triedu `PacketProcessing` v ktorej sa nachádzajú statické metódy na spracovanie pakety. `utils.cpp/hpp` obsahuje pomocné funkcie pre výpis pakiet a niekoľko ďalších funkcionalít.

### Spracovanie vstupných argumentov <a name="Spracovanie-vstupných-argumentov"></a>

Vo funkcii main sa vytvorí inštancia triedy `Parser` ktorá obsahuje metódu pre zpracovanie vstupných argumentov. Následne sa zavolá jej metóda `parser.parse(argc, argv)` ktorá berie ako parametre pole argumentov a ich počet. Táto metóda zpracuje argumenty. Vstupné argumenty sa následne ukladajú do atribútov inštačnej metódy `parser`.

### Vytvorenie a spustenie filtru <a name="Vytvorenie-a-spustenie-filtru"></a>

Po úspešnom spracovaní vstupných argumentov sa vytvorí inštancia triedy `Sniffer` a následne sa zavolá metóda  `void run_sniffer(parser &parser)` alebo  `void run_pcap(parser &parser)` (záleží či spracovávame pakety zo vstupného súboru alebo rozhrania), ktorá berie ako parameter inštačnú triedu `parser`. AK pakety zaznamenávame z rozhrania tak sa inicializuje sniffer pomocou metódy `pcap_t* init_sniffer(parser& parser)` ktorá zahŕňa otvorenie sieťového rozhrania pomocou funkcie `pcap_open_live`. Po inicializácii sniffera sa volá metóda `void build_filter(parser& parser, pcap_t* handle)`, ktorá slúži na vytvorenie a nastavenie filtru pre zachytávanie DNS paketov. Pomocou `pcap_compile` a `pcap_setfilter` sa aplikuje filter na `handle`. Po úspešnej inicializácii a nastavení filtra sa spúšťa zachytávanie sieťových paketov volaním metódy `void capture_packets(parser &parser, pcap_t *handle)`. Táto metóda používa funkciu `pcap_loop`, ktorá kontinuálne zachytáva pakety. Pre viac popísaný význam jednotlivých funkcií filtru viz. [3].

### Výpis zachytených pakiet <a name="Výpis-zachytených-pakiet"></a>

Funkcia `PacketProcessing::parse_packet` je volaná v cykle, ktorý kontinuálne zachytáva pakety na základe nastavených parametrov sniffera. Najprv sa z hlavičky paketu získa časová značka, ktorá označuje čas, keď bol paket zachytený. Časová značka je formátovaná vo funkcii `print_timestamp`, ktorá konvertuje čas z formátu štruktúry `pcap_pkthdr` do reťazca čitateľného pre človeka.

#### Získanie IP adresy
Počas spracovania paketu funkcia `print_ip` extrahuje zdrojovú a cieľovú IP adresu. V závislosti od verzie IP protokolu (IPv4 alebo IPv6) sa vyberie zodpovedajúca hlavička a IP adresy sú premenené na reťazec pomocou funkcie `inet_ntop`. Pre IPv4 sa používa štruktúra `ip`, zatiaľ čo pre IPv6 sa používa štruktúra `ip6_hdr`. Výsledné IP adresy sú následne vypísané, buď podrobne (`verbose` mód), alebo v skrátenom formáte.

#### Spracovanie portov
Funkcie `process_ipv4_port` a `process_ipv6_port` spracovávajú informácie o zdrojovom a cieľovom porte pre UDP pakety. Na základe verzie IP protokolu vypisujú tieto informácie, ak je zapnutý `verbose` mód. Tieto funkcie vypisujú zdrojový a cieľový port pre UDP.

#### Identifikátor a príznaky DNS
Funkcia `print_identifier_and_flags` extrahuje DNS hlavičku z UDP rámca a následne vypíše identifikátor DNS transakcie a jednotlivé príznaky (flags). Ak je povolený `verbose` mód, vypisujú sa detaily ako QR (Query/Response), Opcode, AA (Authoritative Answer), TC (Truncated), RD (Recursion Desired), RA (Recursion Available), AD (Authenticated Data), CD (Checking Disabled) a RCODE (Response Code). Tieto príznaky sú dôležité pre pochopenie správania DNS požiadaviek a odpovedí.

#### DNS informácie
Funkcia `print_dns_information` spracováva jednotlivé sekcie DNS paketu – `Question`, `Answer`, `Authority`, a `Additional` sekcie. Najprv vypíše štatistiku o počte záznamov v každej sekcii, a následne volá pomocné funkcie na ich detailné spracovanie. V prípade, že nie je zapnutý `verbose` mód, vypíše len základné informácie o počte záznamov vo formáte `(QR AN/QD/NS/AR)`.

#### Spracovanie DNS otázok
Funkcia `print_question_sections` spracováva DNS otázky, kde vypíše doménové meno, typ záznamu a triedu záznamu, ak je povolený `verbose` mód. Funkcia taktiež pridáva doménové mená do súboru, ak je to nastavené pomocou parametra `domains_file`.

#### Spracovanie ďalších sekcií
Funkcia `print_other_sections` spracováva záznamy v sekciách `Answer`, `Authority`, a `Additional`. Pre každý záznam vypíše meno, typ záznamu, triedu, TTL (Time-to-Live) a ďalšie detaily. Pomocou funkcie `parse_rdata_and_print` sa následne spracuje obsah záznamov, čo zahŕňa rôzne typy DNS záznamov, ako napríklad A, AAAA, NS, MX a iné.

Každá sekcia je oddelená formátovacou čiarou (`=====================================`) pre lepšiu čitateľnosť výpisu, ak je zapnutý `verbose` mód.


## Ilustrovaná funkcionalita <a name="Ilustrovaná-funkcionalita"></a>

**Vytvorenie filteru**

```
void Sniffer::build_filter(parser &parser, pcap_t *handle)
{
    // Filter expression for DNS over UDP (port 53)
    std::string filter = "udp port 53";
    
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct bpf_program bpf_prog;

    if(!parser.interface.empty())
    {
        // Lookup network details (netmask, IP range, etc.) for the given interface
        if (pcap_lookupnet(parser.interface.c_str(), &net, &mask, errbuf) == PCAP_ERROR)
        {
            std::cerr << "Error: Looking up network: " << errbuf << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    // Compile the filter expression
    if (pcap_compile(handle, &bpf_prog, filter.c_str(), 0, mask) == PCAP_ERROR)
    {
        std::cerr << "Error: Filter compiling: " << pcap_geterr(handle) << std::endl;
        exit(EXIT_FAILURE);
    }

    // Set the compiled filter
    if (pcap_setfilter(handle, &bpf_prog) == PCAP_ERROR)
    {
        std::cerr << "Error: Setting filter: " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&bpf_prog); // Free the filter code if an error occurs
        exit(EXIT_FAILURE);
    }

    // Free the compiled filter after it's set
    pcap_freecode(&bpf_prog); 
}
```

**Parsovanie dát ako napríklad name, adress**

```
std::pair<std::string, int> Utils::parse_data(const u_char *beginning_of_section, const u_char *packet_start)
{
    std::string data;
    const u_char *current_ptr = beginning_of_section;
    int lenght = 0;
    
    // Get lenght of data that is goin to be parsed
    lenght = get_domain_name_length(current_ptr);

    // Loop till 0 value is occured
    while (*current_ptr != 0)
    {
        // Found reference
        if (*current_ptr == 0xc0)
        {
            const u_char *offset = current_ptr + 1;

            // Add offset with the beginning of the raw packet
            current_ptr = packet_start + *offset;
        }
        else // Append the bytes into domain_name
        {
            int label_length = *current_ptr;
            current_ptr++;
            data.append((const char *)current_ptr, label_length);
            current_ptr += label_length;
            if (*current_ptr != 0)
            {
                data.append(".");
            }
        }
    }
    return std::make_pair(data, lenght);
}
```

## Testovanie <a name="Testovanie"></a>

**Program bol úspešne testovaný pomocou posielanie paketov príkazom ping cez terminál.**

**Program bol spustený následujúcim príkazom:** `sudo ./ipk-sniffer -i eth0`

**Testovacie prostredie:** WSL.

**Dôvod testovania:** Overenie funkcionality.

**Výstup:**

```
timestamp: 2024-04-22T14:11:00+02:00
src MAC: 01:00:5E:7F:FF:FA
dst MAC: 00:15:5D:53:5D:66
frame length: 216 bytes
src IP: 172.18.208.1
dst IP: 239.255.255.250
src port: 55227
dst port: 1900

0x0000: 01 00 5e 7f ff fa 00 15  5d 53 5d 66 08 00 45 00   ..^..... ]S]f..E.
0x0010: 00 ca 83 5b 00 00 01 11  c9 b9 ac 12 d0 01 ef ff   ...[.... ........
0x0020: ff fa d7 bb 07 6c 00 b6  b1 99 4d 2d 53 45 41 52   .....l.. ..M-SEAR
0x0030: 43 48 20 2a 20 48 54 54  50 2f 31 2e 31 0d 0a 48   CH * HTT P/1.1..H
0x0040: 4f 53 54 3a 20 32 33 39  2e 32 35 35 2e 32 35 35   OST: 239 .255.255
0x0050: 2e 32 35 30 3a 31 39 30  30 0d 0a 4d 41 4e 3a 20   .250:190 0..MAN: 
0x0060: 22 73 73 64 70 3a 64 69  73 63 6f 76 65 72 22 0d   "ssdp:di scover".
0x0070: 0a 4d 58 3a 20 31 0d 0a  53 54 3a 20 75 72 6e 3a   .MX: 1.. ST: urn:
0x0080: 64 69 61 6c 2d 6d 75 6c  74 69 73 63 72 65 65 6e   dial-mul tiscreen
0x0090: 2d 6f 72 67 3a 73 65 72  76 69 63 65 3a 64 69 61   -org:ser vice:dia
0x00a0: 6c 3a 31 0d 0a 55 53 45  52 2d 41 47 45 4e 54 3a   l:1..USE R-AGENT:
0x00b0: 20 47 6f 6f 67 6c 65 20  43 68 72 6f 6d 65 2f 31    Google  Chrome/1
0x00c0: 32 34 2e 30 2e 36 33 36  37 2e 36 31 20 57 69 6e   24.0.636 7.61 Win
0x00d0: 64 6f 77 73 0d 0a 0d 0a                            dows....

```

**Porovanie výstupu:**  Výstup bol zhodný s očakávaným výstupom.


## Bibliografia <a name="Bibliografia"></a>

[1]: NESFIT . (2024). Documentation Instructions , IPK Projects 2024 [online]. Publisher: Brno University of Technology. Retrieved March 31, 2024, [cit. 2024-04-15] Available at: https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024#documentation-instructions

[2]: Vladimir Vesely . (2024). Project 2 Zeta , IPK Projects 2024 [online]. Publisher: Brno University of Technology. Retrieved March 31, 2024, [cit. 2024-04-15] Available at: https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/src/branch/master/Project%202/zeta

[3]: ENGRSALMANSHAIKH . (DECEMBER 9, 2014). NETWORK PACKET SNIFFER C++ [online]. Publisher: UNCATEGORIZED . Retrieved April 31, 2024, [cit. 2024-04-15] Available at: https://engrsalmanshaikh.wordpress.com/2014/12/09/network-packet-sniffer-c/