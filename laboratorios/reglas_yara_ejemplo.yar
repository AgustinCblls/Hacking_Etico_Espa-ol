/*
  Regla YARA educativa para triage estatico de scripts/archivos sospechosos en laboratorio DFIR (Tomo IV).
  No detecta una familia concreta de malware; ilustra sintaxis, metadatos y condiciones combinadas.
*/
rule Lab_Triage_Script_Ofuscado_Generico
{
    meta:
        author = "Hacking Etico Español"
        description = "Identifica indicadores basicos de ofuscacion en scripts de texto para revision manual"
        date = "2026-11-22"
        severity = "medium"

    strings:
        $ps_enc1 = "FromBase64String" ascii wide nocase
        $ps_enc2 = "EncodedCommand" ascii wide nocase
        $ps_iex  = "Invoke-Expression" ascii wide nocase
        $js_eval = "eval(atob(" ascii nocase
        $js_chr  = "String.fromCharCode" ascii nocase

    condition:
        filesize < 512KB and (
            ($ps_enc1 and $ps_iex) or
            ($ps_enc2 and $ps_iex) or
            ($js_eval and $js_chr)
        )
}
