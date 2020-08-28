// Add a caption
chartSpace.HasChartSpaceTitle = true;
chartSpace.ChartSpaceTitle.Caption = "IIS Reporting";
chartSpace.ChartSpaceTitle.Font.Size = 8;
chartSpace.ChartSpaceTitle.Position = chartSpace.Constants.chTitlePositionBottom;

// Change the background color
chart.PlotArea.Interior.Color = chartSpace.Constants.chColorNone;