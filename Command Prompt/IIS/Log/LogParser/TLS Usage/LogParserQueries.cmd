REM 01 - Protocol
LogParser.exe "SELECT Protocol, COUNT(*) As Number INTO 01_Protocol.csv FROM u_ex*_TLS.log GROUP BY Protocol ORDER BY Number DESC" -i:W3C -o:CSV -stats:OFF
REM 02 - Protocol Chart
LogParser.exe "SELECT Protocol, COUNT(*) As Number INTO 02_Protocol.gif FROM u_ex*_TLS.log GROUP BY Protocol ORDER BY Number DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"Protocol used" -stats:OFF
REM 03 - Protocol Distribution
LogParser.exe "SELECT Protocol, COUNT(*) AS Percent INTO 03_ProtocolDistribution.gif FROM u_ex*_TLS.log GROUP BY Protocol ORDER BY Percent DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -chartType:PieExploded3D -chartTitle:"Protocol Distribution" -stats:OFF
REM 04 - Cipher
LogParser.exe "SELECT Cipher, COUNT(*) As Number INTO 04_Cipher.csv FROM u_ex*_TLS.log GROUP BY Cipher ORDER BY Number DESC" -i:W3C -o:CSV -stats:OFF
REM 05 - Cipher Chart
LogParser.exe "SELECT Cipher, COUNT(*) As Number INTO 05_Cipher.gif FROM u_ex*_TLS.log GROUP BY Cipher ORDER BY Number DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"Cipher used" -stats:OFF
REM 06 - Cipher Distribution
LogParser.exe "SELECT Cipher, COUNT(*) AS Percent INTO 06_CipherDistribution.gif FROM u_ex*_TLS.log GROUP BY Cipher ORDER BY Percent DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -chartType:PieExploded3D -chartTitle:"Cipher Distribution" -stats:OFF
REM 07 - Cipher
LogParser.exe "SELECT Hash, COUNT(*) As Number INTO 07_Hash.csv FROM u_ex*_TLS.log GROUP BY Hash ORDER BY Number DESC" -i:W3C -o:CSV -stats:OFF
REM 08 - Hash Chart
LogParser.exe "SELECT Hash, COUNT(*) As Number INTO 08_Hash.gif FROM u_ex*_TLS.log GROUP BY Hash ORDER BY Number DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"Hash used" -stats:OFF
REM 09 - Hash Distribution
LogParser.exe "SELECT Hash, COUNT(*) AS Percent INTO 09_HashDistribution.gif FROM u_ex*_TLS.log GROUP BY Hash ORDER BY Percent DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -chartType:PieExploded3D -chartTitle:"Hash Distribution" -stats:OFF
REM 10 - KeyExchange
LogParser.exe "SELECT KeyExchange, COUNT(*) As Number INTO 10_KeyExchange.csv FROM u_ex*_TLS.log GROUP BY KeyExchange ORDER BY Number DESC" -i:W3C -o:CSV -stats:OFF
REM 11 - KeyExchange Chart
LogParser.exe "SELECT KeyExchange, COUNT(*) As Number INTO 11_KeyExchange.gif FROM u_ex*_TLS.log GROUP BY KeyExchange ORDER BY Number DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"KeyExchange used" -stats:OFF
REM 12 - KeyExchange Distribution
LogParser.exe "SELECT KeyExchange, COUNT(*) AS Percent INTO 12_KeyExchangeDistribution.gif FROM u_ex*_TLS.log GROUP BY KeyExchange ORDER BY Percent DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -chartType:PieExploded3D -chartTitle:"KeyExchange Distribution" -stats:OFF
REM 13 - User-Agent
LogParser.exe "SELECT cs(User-Agent), COUNT(*) As Number INTO 13_User_Agent.csv FROM u_ex*_TLS.log GROUP BY cs(User-Agent) ORDER BY Number DESC" -i:W3C -o:CSV -stats:OFF
REM 14 - User-Agent Chart
LogParser.exe "SELECT cs(User-Agent), COUNT(*) As Number INTO 14_User_Agent.gif FROM u_ex*_TLS.log GROUP BY cs(User-Agent) ORDER BY Number DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"User-Agent used" -stats:OFF
REM 15 - User-Agent Distribution
LogParser.exe "SELECT cs(User-Agent), COUNT(*) AS Percent INTO 15_User_AgentDistribution.gif FROM u_ex*_TLS.log GROUP BY cs(User-Agent) ORDER BY Percent DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -chartType:PieExploded3D -chartTitle:"User-Agent Distribution" -stats:OFF
REM 16 - Protocol, Cipher, Hash, KeyExchange
LogParser.exe "SELECT  Protocol, Cipher, Hash, KeyExchange, COUNT(*) AS Number INTO 16_Protocol_Cipher_Hash_KeyExchange.csv FROM u_ex*_TLS.log GROUP BY Protocol, Cipher, Hash, KeyExchange ORDER BY Number DESC" -i:W3C -o:CSV -stats:OFF
REM 17 - Protocol, Cipher, Hash, KeyExchange, User-Agent
LogParser.exe "SELECT  Protocol, Cipher, Hash, KeyExchange, cs(User-Agent) as User-Agent, COUNT(*) AS Number INTO 17_Protocol_Cipher_Hash_KeyExchange_User_Agent.csv FROM u_ex*_TLS.log GROUP BY Protocol, Cipher, Hash, KeyExchange, User-Agent ORDER BY Protocol, Cipher, Hash, KeyExchange, Number DESC" -i:W3C -o:CSV -stats:OFF