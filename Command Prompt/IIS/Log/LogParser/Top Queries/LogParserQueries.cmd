REM 01 - Total Requests Count
LogParser.exe "SELECT COUNT(*) AS Hits FROM u_ex*.log TO '01_IISHC_TotalRequestsCount.csv'" -i:W3C -o:CSV -stats:OFF
REM 02 - Total Distinct Client IP Count
LogParser.exe "SELECT COUNT(DISTINCT c-ip) AS Counts FROM u_ex*.log TO '02_IISHC_TotalDistinctClientIP.csv'" -i:W3C -o:CSV -stats:OFF
REM 03 - Top 20 Hits
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem), COUNT(*) AS Hits INTO '03_IISHC_Top_20Hits.csv' FROM u_ex*.log GROUP BY TO_LOWERCASE(cs-uri-stem) ORDER BY Hits DESC" -i:W3C -o:CSV -stats:OFF
REM 04 - Top 20 Hits Chart
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem), COUNT(*) AS Hits INTO 04_IISHC_Top_20Hits.gif FROM u_ex*.log GROUP BY TO_LOWERCASE(cs-uri-stem) ORDER BY Hits DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"Top 20 Hits" -stats:OFF
REM 05 - Top 20 ASPX Hits
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem), COUNT(*) AS Hits INTO '05_IISHC_Top_20ASPXHits.csv' FROM u_ex*.log WHERE TO_LOWERCASE(cs-uri-stem) LIKE '%%.aspx' GROUP BY TO_LOWERCASE(cs-uri-stem) ORDER BY Hits DESC" -i:W3C -o:CSV -stats:OFF
REM 06 - Top 20 ASPX Hits Chart
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem), COUNT(*) AS Hits INTO 06_IISHC_Top_20ASPXHits.gif FROM u_ex*.log WHERE TO_LOWERCASE(cs-uri-stem) LIKE '%%.aspx' GROUP BY TO_LOWERCASE(cs-uri-stem) ORDER BY Hits DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"Top 20 ASPX Hits" -stats:OFF
REM 07 - Top 20 ASP Hits
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem), COUNT(*) AS Hits INTO '07_IISHC_Top_20ASPHits.csv' FROM u_ex*.log WHERE TO_LOWERCASE(cs-uri-stem) LIKE '%%.asp' GROUP BY TO_LOWERCASE(cs-uri-stem) ORDER BY Hits DESC" -i:W3C -o:CSV -stats:OFF
REM 08 - Top 20 ASP Hits Chart
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem), COUNT(*) AS Hits INTO 08_IISHC_Top_20ASPHits.gif FROM u_ex*.log WHERE TO_LOWERCASE(cs-uri-stem) LIKE '%%.asp' GROUP BY TO_LOWERCASE(cs-uri-stem) ORDER BY Hits DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"Top 20 ASP Hits" -stats:OFF
REM 09 - Top 20 Client IP Addresses
LogParser.exe "SELECT Top 20 c-ip, COUNT(*) AS Hits INTO '09_IISHC_Top_20ClientIP.csv' FROM u_ex*.log GROUP BY c-ip ORDER BY Hits DESC" -i:W3C -o:CSV -stats:OFF
REM 10 - Top 20 Client IP Addresses Chart
LogParser.exe "SELECT Top 20 c-ip, COUNT(*) AS Hits INTO 10_IISHC_Top_20ClientIP.gif FROM u_ex*.log GROUP BY c-ip ORDER BY Hits DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"Top 20 Client IP Addresses" -stats:OFF
REM 11 - Top 20 Time Consuming Hits (Sum over the period reviewed)
LogParser.exe "SELECT TOP 20 cs-uri-stem, count(*) AS Hits, SUM(time-taken) AS Milliseconds, AVG(time-taken) AS AvgMilliseconds INTO '11_IISHC_Top20TimeConsumingHits.csv' FROM u_ex*.log GROUP BY cs-uri-stem ORDER BY Milliseconds DESC" -i:W3C -o:CSV -stats:OFF
REM 12 - Top 20 Outbound Bytes Consuming Hits (Sum over the period reviewed)
LogParser.exe "SELECT TOP 20 cs-uri-stem, count(*) AS Hits, SUM(sc-bytes) AS OutboundBytes, AVG(sc-bytes) AS AvgOutboundBytes INTO '12_IISHC_Top20OutboundBytesConsumingHits.csv' FROM u_ex*.log GROUP BY cs-uri-stem ORDER BY OutboundBytes DESC" -i:W3C -o:CSV -stats:OFF
REM 13 - Requests Per Hour
LogParser.exe "SELECT TO_LocalTime(QUANTIZE(TO_TIMESTAMP(date, time),3600)) AS Hours, COUNT(*) AS Hits INTO 13_IISHC_RequestsPerHour.gif FROM u_ex*.log GROUP BY Hours ORDER BY Hours" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"Requests Per Hour" -stats:OFF
REM 14 - Outbound Bytes Per Hour
LogParser.exe "SELECT TO_LocalTime(QUANTIZE(TO_TIMESTAMP(date, time),3600)) AS Hours, SUM(sc-bytes) AS Bytes INTO 14_IISHC_OutboundBytesPerHour.gif FROM u_ex*.log GROUP BY Hours ORDER BY Hours" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"Outbound Bytes Per Hour" -stats:OFF
REM 15 - Distinct Client IP Addresses Per Hour (Users Per Hour)
LogParser.exe "SELECT TO_LocalTime(QUANTIZE(TO_TIMESTAMP(date, time),3600)) AS Hours, c-ip AS CIP INTO '15_IISHC_DistinctClientIPPerHour.csv' FROM u_ex*.log GROUP BY Hours, CIP" -i:W3C -o:CSV -stats:OFF
REM 16 - Distinct Client IP Addresses Per Hour (Users Per Hour) Chart
LogParser.exe "SELECT Hours, COUNT(*) as Counts FROM '15_IISHC_DistinctClientIPPerHour.csv' TO 16_IISHC_DistinctClientIPPerHour.gif GROUP BY Hours ORDER BY Hours" -i:CSV -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"Distinct Client IP Addresses Per Hour (Users Per Hour)" -stats:OFF
REM 17 - HTTP Status Counts
LogParser.exe "SELECT DISTINCT sc-status AS Status, COUNT(*) AS Hits INTO '17_IISHC_HTTPStatusCounts.csv' FROM u_ex*.log GROUP BY Status ORDER BY Status ASC" -i:W3C -o:CSV -stats:OFF
REM 18 - HTTP Status Distribution
LogParser.exe "SELECT DISTINCT sc-status AS Status, COUNT(*) AS Percent INTO 18_IISHC_HTTPStatusDistribution.gif FROM u_ex*.log GROUP BY Status ORDER BY Percent DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -chartType:PieExploded3D -chartTitle:"HTTP Status Distribution" -stats:OFF
REM 19 - Top 20 HTTP Status 4XX
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem) as URI, sc-status as HTTPStatus, COUNT(*) AS Hits INTO '19_IISHC_Top_20HTTP4XXErrors.csv' FROM u_ex*.log WHERE sc-status >= 400 AND sc-status = 500 AND sc-status < 600 GROUP BY URI, sc-status ORDER BY Hits DESC" -i:W3C -o:CSV -stats:OFF
REM 20 - HTTP 404 Errors Per Hour
LogParser.exe "SELECT QUANTIZE(TO_TIMESTAMP(date, time),3600) AS Hours, COUNT(*) AS Errors INTO 20_IISHC_HTTP404ErrorsPerHour.gif FROM u_ex*.log WHERE sc-status = 404 GROUP BY Hours ORDER BY Hours" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"HTTP 404 Errors Per Hour" -stats:OFF
REM 21 - Top 20 HTTP 404 Errors
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem), COUNT(*) AS Hits INTO '21_IISHC_Top_20HTTP404Errors.csv' FROM u_ex*.log WHERE sc-status = 404 GROUP BY TO_LOWERCASE(cs-uri-stem) ORDER BY Hits DESC" -i:W3C -o:CSV -stats:OFF
REM 22 - Top 20 HTTP Status 5XX
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem) as URI, sc-status as HTTPStatus, COUNT(*) AS Hits INTO '22_IISHC_Top_20HTTP5XXErrors.csv' FROM u_ex*.log WHERE sc-status >= 500 AND sc-status < 600 GROUP BY URI, sc-status ORDER BY Hits DESC" -i:W3C -o:CSV -stats:OFF
REM 23 - HTTP 500 Errors/Hour
LogParser.exe "SELECT TO_LocalTime(QUANTIZE(TO_TIMESTAMP(date, time),3600)) AS Hours, COUNT(*) AS Errors INTO 23_IISHC_HTTP500ErrorsPerHour.gif FROM u_ex*.log WHERE sc-status = 500 GROUP BY Hours ORDER BY Hours" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"HTTP 500 Errors Per Hour" -stats:OFF
REM 24 - Top 20 HTTP 500 Errors
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem), COUNT(*) AS Hits INTO '24_IISHC_Top_20HTTP500Errors.csv' FROM u_ex*.log WHERE sc-status = 500 GROUP BY TO_LOWERCASE(cs-uri-stem) ORDER BY Hits DESC" -i:W3C -o:CSV -stats:OFF
REM 25 - Top 20 Average Longest Processing Requests
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem) AS URL, COUNT(TO_LOWERCASE(cs-uri-stem)) AS Hits, AVG(sc-bytes) AS sc-bytes, AVG(cs-bytes) AS cs-bytes, MAX(time-taken) as Max, MIN(time-taken) as Min, AVG(time-taken) as Avg INTO '25_IISHC_Top_20AvgLongestProcRequests.csv' FROM u_ex*.log GROUP BY URL ORDER BY AVG(time-taken) DESC" -i:W3C -o:CSV -stats:OFF
REM 26 - Top 20 Longest Processing Requests
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem) AS URL, TO_DATE( TO_LOCALTIME( TO_TIMESTAMP(date, time))) AS date, TO_TIME( TO_LOCALTIME( TO_TIMESTAMP(date, time))) AS time, sc-bytes, cs-bytes, sc-status, time-taken INTO '26_IISHC_Top_20LongestProcRequests.csv' FROM u_ex*.log ORDER BY time-taken DESC" -i:W3C -o:CSV -stats:OFF
REM 27 - Average/Max Processing Time Per Hour
LogParser.exe "SELECT TO_LocalTime(QUANTIZE(TO_TIMESTAMP(date, time),3600)) AS Hours, AVG(time-taken) AS Avg, MAX(time-taken) AS Max INTO 27_IISHC_AvgMaxProcTimePerHour.gif FROM u_ex*.log WHERE sc-status = 200 GROUP BY Hours ORDER BY Hours" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:Line -groupsize:800x600 -chartTitle:"Average/Max Processing Time Per Hour (ms)" -stats:OFF
REM 28 - Aggregated Average Processing Time Per Hour
LogParser.exe "SELECT TO_LocalTime(quantize(time,3600)) AS Hours, AVG(time-taken) AS Avg INTO 28_IISHC_AggregatedAvgProcTimePerHourRadar.gif FROM u_ex*.log WHERE sc-status = 200 GROUP BY Hours ORDER BY Hours" -i:IISW3C -recurse:-1 -o:CHART -charttype:RadarLineFilled -groupsize:800x600 -chartTitle:"Aggregated Average Processing Time Per Hour" -stats:OFF
REM 29 - Processing Time Per Extension
LogParser.exe "SELECT EXTRACT_EXTENSION(TO_LOWERCASE(cs-uri-stem)) AS Extension, MUL(PROPSUM(time-taken),100.0) AS ProcessingTime INTO 29_IISHC_ProcTimePerExt.gif FROM u_ex*.log GROUP BY Extension ORDER BY ProcessingTime DESC" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:PieExploded3D -groupsize:800x600 -chartTitle:"Processing Time Per Extension" -categories:off -stats:OFF
REM 30 - Outbound BandWidth In MBps
LogParser.exe "SELECT DIV(DIV(MUL(1.0, SUM(sc-bytes)),1048576), 86399) AS OutboundBandWidthInMBps INTO '30_IISHC_OutboundBandWidthInMBps.csv' FROM u_ex*.log" -i:W3C -o:CSV -stats:OFF
REM 31 - Requests Per Second
LogParser.exe "SELECT DIV(MUL(1.0, COUNT(*)), 86399) AS RequestsPerSecond FROM u_ex*.log TO '31_IISHC_RequestsPerSecond.csv'" -i:W3C -o:CSV -stats:OFF
REM 32 - HTTP 400 Errors/Hour
LogParser.exe "SELECT TO_LocalTime(QUANTIZE(TO_TIMESTAMP(date, time),3600)) AS Hours, COUNT(*) AS Errors INTO 32_IISHC_HTTP400ErrorsPerHour.gif FROM u_ex*.log WHERE sc-status = 400 GROUP BY Hours ORDER BY Hours" -i:W3C -config:"LogParserScript.js" -o:CHART -charttype:ColumnClustered -groupsize:800x600 -chartTitle:"HTTP 400 Errors Per Hour" -stats:OFF
REM 33 - Top 20 HTTP 400 Errors
LogParser.exe "SELECT Top 20 TO_LOWERCASE(cs-uri-stem), COUNT(*) AS Hits INTO '33_IISHC_Top_20HTTP400Errors.csv' FROM u_ex*.log WHERE sc-status = 400 GROUP BY TO_LOWERCASE(cs-uri-stem) ORDER BY Hits DESC" -i:W3C -o:CSV -stats:OFF