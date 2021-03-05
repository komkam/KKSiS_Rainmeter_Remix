;---- Background ----

[Background]
	Meter=Shape
	Shape=Ellipse #CRadius#,#CRadius#,#CRadius#,#CRadius# | Fill Color #Circle-BGColor# | StrokeWidth 0
	DynamicVariables=1
	AntiAlias=1
	Updatedivider=-1

[RoundlineShadow]
	Meter=Shape
	Shape=Ellipse #CRadius#,#CRadius#,#CRadius#,#CRadius# | StrokeWidth 0 | Fill RadialGradient CircleBGGradient
	CircleBGGradient=0,0,0,0 | #Circle-RLShadowColor#,0 ; 1.0 | #Circle-RLShadowColor#,80 ; 0.92 | #Circle-RLShadowColor#,80 ; 0.85 | #Circle-RLShadowColor#,0 ; 0.3 | #Circle-RLShadowColor#,0 ; 0.01
	DynamicVariables=1
	AntiAlias=1
	Hidden=#Circle-HideRLShadow#
	Updatedivider=-1

[BackgroundShadow]
	Meter=Shape
	Shape=Ellipse #CRadius#,#CRadius#,#CRadius#,#CRadius# | StrokeWidth 0 | Fill RadialGradient CircleBGGradient
	CircleBGGradient=0,0,0,0 | #Circle-BGShadowColor#,0 ; 1 | #Circle-BGShadowColor#,10 ; 0.8 | #Circle-BGShadowColor#,100 ; 0
	DynamicVariables=1
	AntiAlias=1
	Hidden=#Circle-HideBGShadow#
	Updatedivider=-1


;---- Roundline ----

[ColoredRoundlineBack]
	Meter=Shape
	Shape=Arc (#CRadius#*2*0.505),(#CRadius#*2*0.0855),(#CRadius#*2*0.795),(#CRadius#*2*0.792),(#CRadius#*2*0.415),*,*,0 | StrokeWidth (#CRadius#*2*0.091) | Stroke LinearGradient Circle-RoundlineFillStyle#Circle-RoundlineFillStyle#
	Shape2=Arc (#CRadius#*2*0.495),(#CRadius#*2*0.0855),(#CRadius#*2*0.205),(#CRadius#*2*0.792),(#CRadius#*2*0.415),*,*,1 | StrokeWidth (#CRadius#*2*0.091) | Stroke LinearGradient Circle-RoundlineFillStyle#Circle-RoundlineFillStyle#
	Circle-RoundlineFillStyle1=0 | #Circle-RoundlineFillColor1# ; 1.0 | #Circle-RoundlineFillColor1# ; 0.01
	Circle-RoundlineFillStyle2=90 | #Circle-RoundlineFillColor1# ; 1.0 |  #Circle-RoundlineFillColor1# ; (#Circle-RoundlineFillArc#+0.3) | #Circle-RoundlineFillColor3# ; (#Circle-RoundlineFillArc#-0.3) | #Circle-RoundlineFillColor3# ; 0.01
	Circle-RoundlineFillStyle3=90 | #Circle-RoundlineFillColor1# ; 1.0 | #Circle-RoundlineFillColor2# ; #Circle-RoundlineFillArc# | #Circle-RoundlineFillColor3# ; 0.01
	DynamicVariables=1
	AntiAlias=1
	Updatedivider=-1

[Roundline-Left]
	StartAngle=(Rad(-90.74))
	RotationAngle=(Rad(-135.26))
	LineColor=#Circle-BarColor#	
	LineStart=(#CRadius#*0.74)
	LineLength=(#CRadius#*0.92)
	W=(#CRadius#*2)
	H=(#CRadius#*2)
	Solid=1
	AntiAlias=1
	DynamicVariables=1

[Roundline-Right]
	StartAngle=(Rad(-89.26))
	RotationAngle=(Rad(+135.26))
	LineColor=#Circle-BarColor#	
	LineStart=(#CRadius#*0.74)
	LineLength=(#CRadius#*0.92)
	W=(#CRadius#*2)
	H=(#CRadius#*2)
	Solid=1
	AntiAlias=1
	DynamicVariables=1


;---- Stroke ----

[Roundline-InnerStroke]
	Meter=Roundline
	StartAngle=(Rad(134))
	RotationAngle=(Rad(272))
	LineColor=#Circle-DividerColor#
	LineStart=(#CRadius#*0.72)
	LineLength=(#CRadius#*0.741)
	W=(#CRadius#*2)
	H=(#CRadius#*2)
	Solid=1
	AntiAlias=1
	DynamicVariables=1
	Updatedivider=-1

[Roundline-OuterStroke]
	Meter=Roundline
	StartAngle=(Rad(133.8))
	RotationAngle=(Rad(272.4))
	LineColor=#Circle-DividerColor#
	LineStart=(#CRadius#*0.919)
	LineLength=(#CRadius#*0.94)
	W=(#CRadius#*2)
	H=(#CRadius#*2)
	Solid=1
	AntiAlias=1
	DynamicVariables=1
	Updatedivider=-1


;---- Default Line Divider ----

[LineDivider]
	RotationAngle=(Rad(1))
	LineColor=#Circle-DividerColor#
	Solid=1
	AntiAlias=1
	W=(#CRadius#*2)
	H=(#CRadius#*2)
	LineStart=(#CRadius#*0.75)
	LineLength=(#CRadius#*0.91)
	RotationAngle=(Rad(1.6))
	DynamicVariables=1
	Updatedivider=-1

[LD-135]
	Meter=Roundline
	MeterStyle=LineDivider
	LineStart=(#CRadius#*0.72)
	LineLength=(#CRadius#*0.94)
	RotationAngle=(Rad(1.6))
	StartAngle=(Rad(133.75))
	DynamicVariables=1

[LD0]
	Meter=Roundline
	MeterStyle=LineDivider
	LineStart=(#CRadius#*0.72)
	LineLength=(#CRadius#*0.94)
	RotationAngle=(Rad(1.7))
	StartAngle=(Rad(-90.81))
	DynamicVariables=1

[LD+135]
	Meter=Roundline
	MeterStyle=LineDivider
	LineStart=(#CRadius#*0.72)
	LineLength=(#CRadius#*0.94)
	RotationAngle=(Rad(1.6))
	StartAngle=(Rad(44.60))
	DynamicVariables=1


;---- Glossy Effect ----

[GlossyEffectStyle]
	Shape=Arc (#CRadius#),(#CRadius#*2*0.05),(#CRadius#*2*0.820),(#CRadius#*2*0.816),(#CRadius#*2*0.450),*,*,0 | StrokeWidth (#CRadius#*2*0.02) | Stroke LinearGradient GlossyFillStyle
	Shape2=Arc (#CRadius#),(#CRadius#*2*0.05),(#CRadius#*2*0.180),(#CRadius#*2*0.816),(#CRadius#*2*0.450),*,*,1 | StrokeWidth (#CRadius#*2*0.02) | Stroke LinearGradient GlossyFillStyle2
	Shape3=Arc (#CRadius#),(#CRadius#*2*0.06),(#CRadius#*2*0.814),(#CRadius#*2*0.81),(#CRadius#*2*0.440),*,*,0 | StrokeWidth (#CRadius#*2*0.005) | Stroke LinearGradient GlossyFillStyle3
	Shape4=Arc (#CRadius#),(#CRadius#*2*0.06),(#CRadius#*2*0.186),(#CRadius#*2*0.81),(#CRadius#*2*0.440),*,*,1 | StrokeWidth (#CRadius#*2*0.005) | Stroke LinearGradient GlossyFillStyle4
	GlossyFillStyle=45 | 255,255,255,95 ; 1.0 | 0,0,0,80 ; 0.0
	GlossyFillStyle2=135 | 255,255,255,95 ; 1.0 | 0,0,0,80 ; 0.0
	GlossyFillStyle3=45 | 0,0,0,0 ; 1.0 | 0,0,0,0 ; 0.95 | 255,255,255,100 ; 0.7 | 255,255,255,90 ; 0.6 | 255,255,255,60 ; 0.3 | 0,0,0,40 ; 0.1 | 0,0,0,40 ; 0.0
	GlossyFillStyle4=135 | 0,0,0,0 ; 1.0 | 0,0,0,0 ; 0.95 | 255,255,255,100 ; 0.7 | 255,255,255,90 ; 0.6 | 255,255,255,60 ; 0.3 | 0,0,0,40 ; 0.1 | 0,0,0,40 ; 0.0
	DynamicVariables=1
	Hidden=#Circle-GlossyEffect#
	

;---- Klick on Skin Functions ----

[KlickFunctionsBG]
	Shape=Rectangle 0,0,(#CRadius#*2),(#CRadius#*2),(#CRadius#) | Fill Color 0,0,0,0 | StrokeWidth 0
	DynamicVariables=1
	AntiAlias=1
	UpdateDivider=-1
	MiddleMouseUpAction=[!ShowMeterGroup ChangeCircleSkinSize][!Update]


;---- Graph Style ----

[HWiNFOGraphStyle]
	LineColor=#Circle-RoundlineFillColor1#
	LineColor2=#Circle-RoundlineFillColor3#
	PrimaryColor=0,0,0,0
	SolidColor=#Circle-BGShadowColor#,20
	AutoScale=1
	AntiAlias=1
	W=(#CRadius#*0.99)
	H=(#CRadius#*0.14)
	X=(#CRadius#*0.504)
	Y=(#CRadius#*1.460)
	DynamicVariables=1

[HWiNFOGraphStyle2]
	LineColor=#Circle-RoundlineFillColor1#
	LineColor2=#Circle-RoundlineFillColor3#
	LineColor3=#Circle-RoundlineFillColor2#
	PrimaryColor=0,0,0,0
	SolidColor=#Circle-BGShadowColor#,20
	AutoScale=1
	AntiAlias=1
	W=(#CRadius#*1.4)
	H=(#CRadius#*0.3)
	X=(#CRadius#*0.3)
	Y=(#CRadius#*0.85)
	DynamicVariables=1

[HWiNFOGraphStyle3]
	LineColor=#Circle-Circle-DividerColor#
	LineColor2=#Circle-RoundlineFillColor2#
	LineColor3=#Circle-RoundlineFillColor3#
	LineColor4=#Circle-RoundlineFillColor1#
	PrimaryColor=0,0,0,0
	SolidColor=#Circle-BGShadowColor#,20
	AutoScale=1
	AntiAlias=1
	W=(#CRadius#*1.4)
	H=(#CRadius#*0.3)
	X=(#CRadius#*0.3)
	Y=(#CRadius#*0.85)
	DynamicVariables=1


;---- Change Skin Size ----

[Change-Circle-Size]
	Shape=Rectangle 0,0,(#CRadius#*2),(#CRadius#*2),(#CRadius#*0.1) | Fill Color 0,0,0,80 | StrokeWidth (#CRadius#*0.02) | Stroke Color 255,255,255
	Group=ChangeCircleSkinSize
	DynamicVariables=1
	AntiAlias=1
	Hidden=1
	MouseScrollDownAction=[!SetVariable CRadius "(#CRadius#-#MouseScale# < 30 ? 30 : #CRadius#-#MouseScale#)"][!WriteKeyValue Variables CRadius "(#CRadius#-#MouseScale# < 30 ? 30 : #CRadius#-#MouseScale#)"][!UpdateMeasure *][!UpdateMeter *][!Redraw]
	MouseScrollUpAction=[!SetVariable CRadius "(#CRadius#+#MouseScale#)"][!WriteKeyValue Variables CRadius "(#CRadius#+#MouseScale#)"][!UpdateMeasure *][!UpdateMeter *][!Redraw]
	MouseLeaveAction=[!HideMeterGroup ChangeCircleSkinSize][!Update]
	MiddleMouseUpAction=[!HideMeterGroup ChangeCircleSkinSize][!Update]
	UpdateDivider=-1
	
[Change-Circle-Size-CurrentWidth]
	Measure=Calc
	Formula=(#CRadius#*2)
	DynamicVariables=1

[Change-Circle-Size-WidthDisplay]
	Meter=String
	MeasureName=Change-Circle-Size-CurrentWidth
	Group=ChangeCircleSkinSize
	FontColor=#Circle-FontColor#
	FontStyle=Calibri
	FontSize=(#CRadius#*0.18)
	X=(#CRadius#*0.02)
	Y=0
	Text=%1
	DynamicVariables=1
	Hidden=1




