# Device manuals (RAG grounding documents)

Real, publicly-available manuals used to ground the agent's citations — not fabricated text. If the agent cites a page number, it needs to match what's actually in these files.

## philips-intellivue-data-export-interface-guide.pdf

- **Title:** Data Export Interface Programming Guide — IntelliVue Patient Monitor & Avalon Fetal Monitor
- **Covers:** X2, MP Series, MX Series, FM Series
- **Release:** L.0, part number 4535 645 88011 (ENG)
- **Published:** Philips, Germany, 08/2015, 339 pages
- **Source (public, no login):** https://www.documents.philips.com/doclib/enc/fetch/2000/4504/577242/577243/577247/582636/582882/X2,_MP,_MX_%26_FM_Series_Rel._L.0_Data_Export_Interface_Program._Guide_4535_645_88011_(ENG).pdf

### Real network port data (verified from the actual PDF text — use these, not the earlier 3200/HL7 placeholder)

The monitor's native networking is Philips' proprietary **Data Export Protocol over UDP**, not HL7/TCP:

- **UDP port 24105** — main data exchange (Section 4, "Transport Protocols for the LAN Interface," p. 29): *"The current Protocol version uses the fixed UDP port 24105. All messages sent from the Computer Client to the monitor must use this port number as the destination port number."*
- **UDP port 24005** — device discovery / "Connect Indication Event" broadcast (Section 5, p. 53).

**Note:** this manual does not mention HL7 anywhere. HL7 export from an IntelliVue monitor would require routing through the separate IntelliVue Information Center (central station) product — a different manual, not this one. Any demo copy/citation referencing "port 3200" or "HL7" against *this* document is inaccurate and should use the real numbers above instead.
