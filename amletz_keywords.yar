rule amletz_keywords
{
    meta:
      author    = "INCD"
      category  = "MALWARE"
      
    strings:
        $a1_1	= "JDBC"
        $a1_2	= "eval"
        $a1_3	= "cmd/c"
        

        
    condition:
        1 of ($a1_*)
}

