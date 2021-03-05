[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
;---- Sensors ----
@Include6=#@#Windows-Sensors.inc


;---- Standard Windows Measures ----

[Measure_MaxRAM]
Measure				=PhysicalMemory
Total				=1

[Measure_RAM0]
Measure				=PhysicalMemory

[Measure_RAM1]
Measure				=Calc
Formula				=Measure_MaxRAM-Measure_RAM0

[Measure_MaxSwap]
Measure				=SwapMemory
Total				=1

[Measure_Swap0]
Measure				=SwapMemory

[Measure_Swap1]
Measure				=Calc
Formula				=Measure_MaxSwap-Measure_Swap0

[Measure_RAMPercentage0]
Measure				=Calc
Formula				=100-100*(Measure_RAM0/Measure_MaxRAM)
MaxValue			=100
MinValue			=0

[Measure_RAMPercentage1]
Measure				=Calc
Formula				=100*(Measure_RAM0/Measure_MaxRAM)
MaxValue			=100
MinValue			=0

[Measure_SwapPercentage0]
Measure				=Calc
Formula				=100-100*(Measure_Swap0/Measure_MaxSwap)

[Measure_SwapPercentage1]
Measure				=Calc
Formula				=100*(Measure_Swap0/Measure_MaxSwap)


;---- Standard Meter ----

[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo | PCenterMid
	Y=(#PHeight#*0.03)
	Text=#VarUsed#
	AutoScale=1
	NumOfDecimals=0
	
[Info2Text]
	Meter=String
	MeterStyle=PText | PSize0 | PCenterMid
	Y=(#PHeight#*0.2)
	MeasureName=Measure_RAM0
	MeasureName2=Measure_RAM1
	MeasureName3=Measure_RAMPercentage1
	MeasureName4=Measure_RAMPercentage0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1

[Info3Text]
	Meter=String
	MeterStyle=PText | PSize6 | PCenterMid
	MeasureName=Measure_MaxRAM
	Y=(#PHeight#*0.43)
	Text=(%1B RAM)
	AutoScale=1
	NumOfDecimals=0
	
[Info4Text]
	Meter=String
	MeterStyle=PText | PInfo | PCenterMid
	MeasureName=Measure_Swap0
	MeasureName2=Measure_Swap1
	MeasureName3=Measure_SwapPercentage1
	MeasureName4=Measure_SwapPercentage0
	Y=(#PHeight#*0.64)
	Text=%1B
	NumOfDecimals=1
	AutoScale=1

[Info5Text]
	Meter=String
	MeterStyle=PText | PSize6 | PCenterMid
	MeasureName=Measure_MaxSwap
	Y=(#PHeight#*0.77)
	Text=(%1B Swap)
	AutoScale=1
	NumOfDecimals=0
	
[Title]
	Meter=String
	MeasureName=Measure_RAMName
	MeterStyle=PText | PTitle
	Text=#RAMNameWin#


;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#RAMHideGraph#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=Measure_RAMPercentage#RAMShowFreeSpace#
UpdateDivider=1
Hidden=#RAMHideGraph#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#RAMHideGraph#


;---- Options ----

[Selection]
	Measure=Calc
	Formula=#RAMShowPercentage#+#RAMShowFreeSpace#
	UpdateRate=-1
	IfCondition=(#RAMShowPercentage# = 0) && (#RAMShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info1Text Text "#VarUsed#"][!SetOption Info2Text Text "%1B"][!SetOption Info4Text Text "%1B"]
	IfCondition2=(#RAMShowPercentage# = 0) && (#RAMShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info1Text Text "#VarFree#"][!SetOption Info2Text Text "%2B"][!SetOption Info4Text Text "%2B"]
	IfCondition3=(#RAMShowPercentage# = 1) && (#RAMShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info1Text Text "#VarUsed#"][!SetOption Info2Text Text "%3%"][!SetOption Info4Text Text "%3%"]
	IfCondition4=(#RAMShowPercentage# = 1) && (#RAMShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info1Text Text "#VarFree#"][!SetOption Info2Text Text "%4%"][!SetOption Info4Text Text "%4%"]
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!CommandMeasure SpecialFunction Run]

[SpecialFunction]
Measure=Plugin
Plugin=RunCommand
Parameter=perfmon/res

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size