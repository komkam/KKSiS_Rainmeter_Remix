[Variables]
@Include5=#@#Include\PanelStyleSmall.inc


;---- Measures ----

[RecycleBinSize]
Measure				=RecycleManager
RecycleType			=SIZE
UpdateDivider		=1
IfCondition			=(RecycleBinSize = 0)
IfTrueAction		=[!HideMeterGroup BinFull][!ShowMeter BinImageEmpty]
IfFalseAction		=[!ShowMeterGroup BinFull][!HideMeter BinImageEmpty]

[BinColor]
Measure				=Calc
Formula				=#Panel-TRColored#
IfCondition			=BinColor = 1
IfTrueAction		=[!SetOption BinImageEmpty ImageTint #Panel-BarFillColor3#][!SetOption BinImageFull ImageTint #Panel-BarFillColor1#]
IfFalseAction		=[!SetOption BinImageEmpty ImageTint ""][!SetOption BinImageFull ImageTint ""]
IfCondition2		=(#Panel-TRColored# = 0) && (#TRBinType# = 5)
IfTrueAction2		=[!SetOption BinImageEmpty ImageTint #Panel-ButtonColor#][!SetOption BinImageFull ImageTint #Panel-ButtonColor#]
DynamicVariables	=1
UpdateDivider		=-1


;---- Meters ----

[BinImageEmpty]
	Meter=Image
	ImageName=#@#Images\General\Bin#TRBinType#a.png
	ImageTint=
	X=(#PHeight#*0.05)
	Y=(#PHeight#*0.06)
	W=(#PHeight#*0.25)
	H=(#PHeight#*0.25)
	DynamicVariables=1

[BinImageFull]
	Meter=Image
	ImageName=#@#Images\General\Bin#TRBinType#b.png
	ImageTint=
	X=(#PHeight#*0.05)
	Y=(#PHeight#*0.06)
	W=(#PHeight#*0.25)
	H=(#PHeight#*0.25)
	DynamicVariables=1
	Group=BinFull

[BinSizeText]
	Meter=String
	MeterStyle=PText | PSize5
	StringAlign=Left
	Text=#VarTotal#
	X=(#PHeight#*0.4)
	Y=(#PHeight#*0.04)

[BinSize]
	Meter=String
	MeterStyle=PText | PSize2
	MeasureName=RecycleBinSize
	StringAlign=Left
	X=0r
	Y=(#PHeight#*0.1)r
	AutoScale=1
	NumOfDecimals=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!CommandMeasure RecycleBinSize OpenBin]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size