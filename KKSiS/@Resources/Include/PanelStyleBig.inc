;---- Background ----

[PanelBGShadow]
	Meter=Shape
	Shape=Rectangle (#PHeight#*0.072),0,(#PHeight#*1.936),(#PHeight#*0.040),0 | StrokeWidth 0 | Fill LinearGradient BGShadowGradient1
	Shape2=Rectangle (#PHeight#*2.040),(#PHeight#*0.072),(#PHeight#*0.040),(#PHeight#*0.936),0 | StrokeWidth 0 | Fill LinearGradient BGShadowGradient2
	Shape3=Rectangle (#PHeight#*0.072),(#PHeight#*1.040),(#PHeight#*1.936),(#PHeight#*0.040),0 | StrokeWidth 0 | Fill LinearGradient BGShadowGradient3
	Shape4=Rectangle 0,(#PHeight#*0.072),(#PHeight#*0.040),(#PHeight#*0.936),0 | StrokeWidth 0 | Fill LinearGradient BGShadowGradient4
	Shape5=Path MyCorner | StrokeWidth 0 | Fill RadialGradient MyCornerGradient
	Shape6=Path MyCorner | Rotate 90 | Offset (#PHeight#*2.008),0 | StrokeWidth 0 | Fill RadialGradient MyCornerGradient
	Shape7=Path MyCorner | Rotate 180 | Offset (#PHeight#*2.008),(#PHeight#*1.008) | StrokeWidth 0 | Fill RadialGradient MyCornerGradient
	Shape8=Path MyCorner | Rotate 270 | Offset 0,(#PHeight#*1.008) | StrokeWidth 0 | Fill RadialGradient MyCornerGradient
	MyCorner=(#PHeight#*0.072),0 | LineTo (#PHeight#*0.072),(#PHeight#*0.040) | CurveTo (#PHeight#*0.040),(#PHeight#*0.072),(#PHeight#*0.044),(#PHeight#*0.044) | LineTo 0,(#PHeight#*0.072) | CurveTo (#PHeight#*0.072),0,0,0
	BGShadowGradient1=90 | #Panel-BGShadowColor#,10 ; 1.0 | #Panel-BGShadowColor#,100 ; 0.0
	BGShadowGradient2=180 | #Panel-BGShadowColor#,10 ; 1.0 | #Panel-BGShadowColor#,100 ; 0.0
	BGShadowGradient3=270 | #Panel-BGShadowColor#,10 ; 1.0 | #Panel-BGShadowColor#,100 ; 0.0
	BGShadowGradient4=0 | #Panel-BGShadowColor#,10 ; 1.0 | #Panel-BGShadowColor#,100 ; 0.0
	MyCornerGradient=(#PHeight#*0.034),(#PHeight#*0.034),*,*,(#PHeight#*0.1),(#PHeight#*0.1) | #Panel-BGShadowColor#,0 ; 1.0 | #Panel-BGShadowColor#,0 ; 0.75 | #Panel-BGShadowColor#,100 ; 0.3 | #Panel-BGShadowColor#,100 ; 0.1
	AntiAlias=1
	DynamicVariables=1
	Hidden=#Panel-HideBGShadow#
	UpdateDivider=-1
	
[Panel]
	Meter=Shape
	Shape=Rectangle (#PHeight#*0.040),(#PHeight#*0.040),(#PHeight#*2),(#PHeight#),(#PHeight#*0.032) | Fill Color #Panel-BGColor# | StrokeWidth (#PHeight#*0.01*#Panel-Frame#) | Stroke Color #Panel-StrokeColor#
	AntiAlias=1
	DynamicVariables=1
	UpdateDivider=-1
	
[PanelShadow]
	Meter=Shape
	Shape=Rectangle (#PHeight#*0.04),(#PHeight#*0.040),(#PHeight#*2),(#PHeight#),0 | StrokeWidth 0 | Fill RadialGradient PanelShadowGradient
	PanelShadowGradient=0,0,0,0 | #Panel-BGShadowColor#,0 ; 1.0 | #Panel-BGShadowColor#,100 ; 0.0
	AntiAlias=1
	DynamicVariables=1
	Hidden=#Panel-HideShadow#
	UpdateDivider=-1
		
[KlickFunctionsBG]
	Shape=Rectangle (#PHeight#*0.040),(#PHeight#*0.040),(#PHeight#*2),(#PHeight#),0 | Fill Color 0,0,0,0 | StrokeWidth 0
	DynamicVariables=1
	AntiAlias=1
	UpdateDivider=-1
	MiddleMouseUpAction=[!ShowMeterGroup ChangePanelSkinSize][!Update]


;---- Measure Bars ----

[BarStyle-VRx1]
	Shape=Rectangle (#PHeight#*1.95),(#PHeight#*0.05),(#PHeight#*0.06),(#PHeight#*0.98),0 | StrokeWidth 0 | Fill LinearGradient PanelBarFill#Panel-BarFillStyle#
	PanelBarFill1=90 | #Panel-BarFillColor1# ; 1.0 | #Panel-BarFillColor1# ; 0.0
	PanelBarFill2=90 | #Panel-BarFillColor1# ; 1.0 |  #Panel-BarFillColor1# ; (#Panel-BarFillArc#+0.3) | #Panel-BarFillColor3# ; (#Panel-BarFillArc#-0.3) | #Panel-BarFillColor3# ; 0.0
	PanelBarFill3=90 | #Panel-BarFillColor1# ; 1.0 | #Panel-BarFillColor2# ; #Panel-BarFillArc# | #Panel-BarFillColor3# ; 0.0
	DynamicVariables=1
	UpdateDivier=-1

[BarStyle-VRx1Measure]
	Flip=1
	BarColor=#Panel-BarColor#
	SolidColor=0,0,0,0
	BarOrientation=Vertical
	X=(#PHeight#*1.950)
	Y=(#PHeight#*0.05)
	W=(#PHeight#*0.067)
	H=(#PHeight#*0.98)
	AntiAlias=1
	DynamicVariables=1
	UpdateDivider=1

[BarStyle-VRx1Stroke]
	Shape=Rectangle (#PHeight#*1.948),(#PHeight#*0.048),(#PHeight#*0.064),(#PHeight#*0.984),0 | StrokeWidth (#PHeight#*0.006) | Stroke Color #Panel-StrokeColor# | Fill Color 0,0,0,0
	Shape2=Rectangle (#PHeight#*1.95),(#PHeight#*0.244),(#PHeight#*0.06),(#PHeight#*0.006),0 | StrokeWidth 0 | Fill Color #Panel-StrokeColor#
	Shape3=Rectangle (#PHeight#*1.95),(#PHeight#*0.440),(#PHeight#*0.06),(#PHeight#*0.006),0 | StrokeWidth 0 | Fill Color #Panel-StrokeColor#
	Shape4=Rectangle (#PHeight#*1.95),(#PHeight#*0.636),(#PHeight#*0.06),(#PHeight#*0.006),0 | StrokeWidth 0 | Fill Color #Panel-StrokeColor#
	Shape5=Rectangle (#PHeight#*1.95),(#PHeight#*0.832),(#PHeight#*0.06),(#PHeight#*0.006),0 | StrokeWidth 0 | Fill Color #Panel-StrokeColor#
	AntiAlias=1
	DynamicVariables=1
	UpdateDivider=-1


;---- Graph Style ----

[GraphStyleBigPanelHWiNFO]
	LineColor=#Panel-BarFillColor1#
	LineColor2=#Panel-BarFillColor3#
	PrimaryColor=0,0,0,0
	SolidColor=#Panel-BGShadowColor#,20
	AutoScale=1
	AntiAlias=1
	W=(#PHeight#*1.05)
	H=(#PHeight#*0.12)
	X=0r
	Y=(#PHeight#*0.166)r
	DynamicVariables=1

[GraphStyleBigPanelMSIAB]
	LineColor=#Panel-BarFillColor1#
	LineColor2=#Panel-BarFillColor3#
	PrimaryColor=0,0,0,0
	SolidColor=#Panel-BGShadowColor#,20
	AutoScale=1
	AntiAlias=1
	W=(#PHeight#*1.05)
	H=(#PHeight#*0.15)
	X=0r
	Y=(#PHeight#*0.19)r
	DynamicVariables=1

[GraphStyleBigPanelWindows]
	LineColor=#Panel-BarFillColor1#
	LineColor2=#Panel-BarFillColor3#
	PrimaryColor=0,0,0,0
	SolidColor=#Panel-BGShadowColor#,20
	AutoScale=1
	AntiAlias=1
	W=(#PHeight#*1.98)
	H=(#PHeight#*0.2)
	X=(#PHeight#*0.05)
	Y=(#PHeight#*0.4)
	DynamicVariables=1

[GraphStyleLeft]
	LineColor=#Panel-BarFillColor1#
	PrimaryColor=0,0,0,0
	SolidColor=#Panel-BGShadowColor#,20
	AutoScale=1
	AntiAlias=1
	W=(#PHeight#*0.985)
	H=(#PHeight#*0.6)
	X=(#PHeight#*0.05)
	Y=(#PHeight#*0.34)
	DynamicVariables=1

[GraphStyleRight]
	LineColor=#Panel-BarFillColor3#
	PrimaryColor=0,0,0,0
	SolidColor=#Panel-BGShadowColor#,20
	AutoScale=1
	AntiAlias=1
	W=(#PHeight#*0.985)
	H=(#PHeight#*0.6)
	X=(#PHeight#*1.05)
	Y=(#PHeight#*0.34)
	DynamicVariables=1

[GraphStyleBigPanelFullSize]
	LineColor=#Panel-BarFillColor1#
	LineColor2=#Panel-BarFillColor3#
	LineColor3=#Panel-BarFillColor2#
	LineColor4=#Panel-StrokeColor#
	LineColor5=#Panel-BarColor#
	PrimaryColor=0,0,0,0
	SolidColor=#Panel-BGShadowColor#,20
	AutoScale=1
	AntiAlias=1
	X=(#PHeight#*0.97)
	Y=(#PHeight#*0.06)
	H=(#PHeight#*0.82)
	W=(#PHeight#*1.05)
	DynamicVariables=1

;---- Change Skin Size ----

[Change-Panel-Size]
	Shape=Rectangle (#PHeight#*0.040),(#PHeight#*0.040),(#PHeight#*2),(#PHeight#),(#PHeight#*0.032) | Fill Color 0,0,0,80 | StrokeWidth (#PHeight#*0.006) | Stroke Color 255,255,255
	Group=ChangePanelSkinSize
	DynamicVariables=1
	AntiAlias=1
	Hidden=1
	MouseScrollDownAction=[!SetVariable PHeight "(#PHeight#-#MouseScale# < 30 ? 30 : #PHeight#-#MouseScale#)"][!WriteKeyValue Variables PHeight "(#PHeight#-#MouseScale# < 30 ? 30 : #PHeight#-#MouseScale#)"][!UpdateMeasure *][!UpdateMeter *][!Redraw]
	MouseScrollUpAction=[!SetVariable PHeight "(#PHeight#+#MouseScale#)"][!WriteKeyValue Variables PHeight "(#PHeight#+#MouseScale#)"][!UpdateMeasure *][!UpdateMeter *][!Redraw]
	MouseLeaveAction=[!HideMeterGroup ChangePanelSkinSize][!Update]
	MiddleMouseUpAction=[!HideMeterGroup ChangePanelSkinSize][!Update]
	UpdateDivider=-1
	
[Panel-Width]
	Measure=Calc
	Formula=#PHeight#*2
	DynamicVariables=1

[Change-Panel-Size-WidthDisplay]
	Meter=String
	MeasureName=Panel-Width
	Group=ChangePanelSkinSize
	FontColor=#Panel-FontColor#
	FontStyle=Calibri
	StringAlign=Center
	FontSize=(#PHeight#*0.10)
	X=(#PHeight#*1.04)
	Y=(#PHeight#*1.04)
	Text=%1x#PHeight#
	DynamicVariables=1
	Hidden=1
	UpdateDivider=-1






