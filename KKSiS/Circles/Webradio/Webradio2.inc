;---- Measures Volume ----

[VolumeWin]
Measure			=Plugin
Plugin			=Win7AudioPlugin
UpdateDivider	=1

[VolumeWinInverted]
Measure			=Plugin
InvertMeasure	=1
Plugin			=Win7AudioPlugin
UpdateDivider	=1

[VolumeWinPercent]
Measure			=Calc
Formula			=VolumeWin
UpdateDivider	=3
IfCondition		=(VolumeWinPercent = -1) && (#WRActive# = 1)
IfTrueAction	=[!ShowMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfFalseAction	=[!HideMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfCondition2	=(VolumeWinPercent > 0) && (#WRActive# = 1)
IfTrueAction2	=[!HideMeter "ButtonMute"][!ShowMeter "ButtonVol"]
DynamicVariables=1

[VolumeWinSmooth]
Measure			=Calc
Formula			=VolumeWinInverted
AverageSize		=6
UpdateDivider	=1

[FunctionSwitch]
Measure			=Calc
Formula			=#WRShowColoredBtnFrame#
IfCondition		=(#WRShowColoredBtnFrame# = 1)
IfTrueAction	=[!SetVariable CurrentBarColor #Circle-RoundlineFillColor1#]
DynamicVariables=1
Updatedivider	=1


;---- Measures Audiolevel ----

[WinAudioLevel]
	Measure=Plugin
	Plugin=AudioLevel
	Port=Output
	FFTSize=1024
	FFTAttack=15
	FFTDecay=200
	Bands=31
	UpdateDivier=1
[Band0]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=0
[Band1]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=1
[Band2]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=2
[Band3]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=3
[Band4]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=4
[Band5]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=5
[Band6]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=6
[Band7]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=7
[Band8]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=8
[Band9]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=9
[Band10]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=10
[Band11]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=11
[Band12]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=12
[Band13]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=13
[Band14]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=14
[Band15]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=15
[Band16]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=16
[Band17]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=17
[Band18]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=18
[Band19]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=19
[Band20]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=20
[Band21]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=21
[Band22]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=22
[Band23]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=23
[Band24]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=24
[Band25]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=25
[Band26]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=26
[Band27]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=27
[Band28]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=28
[Band29]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=29
[Band30]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=30

	
;---- Roundline 0 - 100 ----

[Measure-Roundline-Left]
Meter=Roundline
MeterStyle=Roundline-Left
MeasureName=VolumeWinSmooth
ValueRemainder=100
Updatedivider=1

[Measure-Roundline-Right]
Meter=Roundline
MeterStyle=Roundline-Right
MeasureName=VolumeWinSmooth
ValueRemainder=100
Updatedivider=1

[LD-20]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-199.3))
[LD-40]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-172.3))
[LD-60]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-145.3))
[LD-80]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-118.3))
UpdateDivider=100
[LD+80]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-62.7))
UpdateDivider=100
[LD+60]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-35.7))
[LD+40]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-8.7))
[LD+20]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(18.3))

[GlossyEffect]
Meter=Shape
MeterStyle=GlossyEffectStyle


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!ShowMeterGroup Stations]
MouseScrollDownAction=[!CommandMeasure "VolumeWin" "ChangeVolume -3"]
MouseScrollUpAction=[!CommandMeasure "VolumeWin" "ChangeVolume +3"]
Updatedivider=-1


;---- Default Cover & Station ----

[SpeakerLogo]
	Meter=Image
	ImageName=#@#Images\General\Speaker.png
	X=(#CRadius#*0.5)
	Y=(#CRadius#*0.5)
	W=(#CRadius#)
	H=(#CRadius#)
	Hidden=#WRActive#
	Group=RadioOff
	DynamicVariables=1
	Updatedivider=-1

[Volume]
	Meter=String
	MeterStyle=CText | CSize6 | CCenter
	MeasureName=VolumeWinPercent
	Y=(#CRadius#*0.16)
	Group=RadioOff
	Hidden=#WRHideVolume#
	Text=Vol %1
	UpdateDivider=3
	DynamicVariables=1

[Title]
	Meter=String
	MeterStyle=CText | CTitle
	Text=Webradio
	Group=RadioOff
	Hidden=#WRActive#
	DynamicVariables=1
	Updatedivider=-1


;---- Active Cover & Station ----

[Cover]
	Meter=Image
	ImageName=#@#Images\Stations\#WRASImage#
	AntiAlias=1
	X=(#CRadius#*0.61)
	Y=(#CRadius#*0.3)
	W=(#CRadius#*0.78)
	H=(#CRadius#*0.78)
	Hidden=#WRInactive#
	Group=Radio
	LeftMouseUpAction=[#WRASTracklist#]
	DynamicVariables=1
	UpdateDivider=10
	Container=CoverContainer

[CoverContainer]
	Meter=Shape
	Shape=Rectangle (#CRadius#*0.3),(#CRadius#*0.3),(#CRadius#*1.4),(#CRadius#*1.4),(#CRadius#*0.7) | StrokeWidth 0 | Fill Color 0,0,0
	DynamicVariables=1
	
[SationText]
	Meter=String
	MeterStyle=CText | CTitle
	Hidden=#WRInactive#
	Group=Radio
	Text=#WRASTitle#
	UpdateDivider=10


;---- Audiolevelmeter ----

[StyleAudioBar]
	Flip=0
	BarColor=#CurrentBarColor#
	SolidColor=#Circle-BGShadowColor#,20
	BarOrientation=Vertical
	Y=(#CRadius#*1.1)
	W=(#CRadius#*0.03)
	H=(#CRadius#*0.29)
	Group=Radio
	AntiAlias=1
	DynamicVariables=1
	Hidden=#WRInactive#
	UpdateDivider=1
	Container=CoverContainer
[MeterBand0]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band0
	X=(#CRadius#*0.295)
[MeterBand1]
	Meter=Bar
	MeasureName=Band1
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.344)
[MeterBand2]
	Meter=Bar
	MeasureName=Band2
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.393)
[MeterBand3]
	Meter=Bar
	MeasureName=Band3
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.442)
[MeterBand4]
	Meter=Bar
	MeasureName=Band4
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.491)
[MeterBand5]
	Meter=Bar
	MeasureName=Band5
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.540)
[MeterBand6]
	Meter=Bar
	MeasureName=Band6
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.589)
[MeterBand7]
	Meter=Bar
	MeasureName=Band7
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.638)
[MeterBand8]
	Meter=Bar
	MeasureName=Band8
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.687)
[MeterBand9]
	Meter=Bar
	MeasureName=Band9
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.736)
[MeterBand10]
	Meter=Bar
	MeasureName=Band10
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.785)
[MeterBand11]
	Meter=Bar
	MeasureName=Band11
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.834)
[MeterBand12]
	Meter=Bar
	MeasureName=Band12
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.883)
[MeterBand13]
	Meter=Bar
	MeasureName=Band13
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.932)
[MeterBand14]
	Meter=Bar
	MeasureName=Band14
	MeterStyle=StyleAudiobar
	X=(#CRadius#*0.981)
[MeterBand15]
	Meter=Bar
	MeasureName=Band15
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.030)
[MeterBand16]
	Meter=Bar
	MeasureName=Band16
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.079)
[MeterBand17]
	Meter=Bar
	MeasureName=Band17
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.128)
[MeterBand18]
	Meter=Bar
	MeasureName=Band18
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.177)
[MeterBand19]
	Meter=Bar
	MeasureName=Band19
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.226)
[MeterBand20]
	Meter=Bar
	MeasureName=Band20
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.275)
[MeterBand21]
	Meter=Bar
	MeasureName=Band21
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.324)
[MeterBand22]
	Meter=Bar
	MeasureName=Band22
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.373)
[MeterBand23]
	Meter=Bar
	MeasureName=Band23
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.422)
[MeterBand24]
	Meter=Bar
	MeasureName=Band24
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.471)
[MeterBand25]
	Meter=Bar
	MeasureName=Band25
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.520)
[MeterBand26]
	Meter=Bar
	MeasureName=Band26
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.569)
[MeterBand27]
	Meter=Bar
	MeasureName=Band27
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.618)
[MeterBand28]
	Meter=Bar
	MeasureName=Band28
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.667)
[MeterBand29]
	Meter=Bar
	MeasureName=Band29
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.716)
[MeterBand30]
	Meter=Bar
	MeasureName=Band30
	MeterStyle=StyleAudiobar
	X=(#CRadius#*1.765)

	
;---- Buttons ----

[ButtonFrame]
	Meter=Shape
	Shape=Rectangle (#CRadius#*0.62),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle# | Fill Color 0,0,0,0
	Shape2=Rectangle (#CRadius#*0.82),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle# | Fill Color 0,0,0,0
	Shape3=Rectangle (#CRadius#*1.02),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle# | Fill Color 0,0,0,0
	Shape4=Rectangle (#CRadius#*1.22),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle#| Fill Color 0,0,0,0
	ButtonFrameColor01=90 | #Circle-ButtonColor# ; 0.0 | #Circle-ButtonColor# ; 1.0
	ButtonFrameColor02=90 | #Circle-ButtonColor# ; 0.0 | #Circle-ButtonColor# ; 1.0
	ButtonFrameColor03=90 | #Circle-ButtonColor# ; 0.0 | #Circle-ButtonColor# ; 1.0
	ButtonFrameColor11=90 | #Circle-RoundlineFillColor1# ; 0.0 | #Circle-RoundlineFillColor1# ; 1.0
	ButtonFrameColor12=90 | #Circle-RoundlineFillColor3# ; 0.0 |  #Circle-RoundlineFillColor1# ; 1.0
	ButtonFrameColor13=90 | #Circle-RoundlineFillColor3# ; 0.0 | #Circle-RoundlineFillColor2# ; 0.5 | #Circle-RoundlineFillColor1# ; 1.0
	DynamicVariables=1
	AntiAlias=1
	Hidden=#WRInactive#
	Group=Radio
	UpdateDivider=-1

[ButtonVol]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVol.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*0.652)	
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonVol ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonVol ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonMute]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVolMute.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*0.652)	
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonMute ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonMute ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonStop]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnStop.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*0.852)	
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonStop ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonStop ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!SetVariable "WRActive" "0"][!WriteKeyValue Variables "WRActive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "1" "#@#Variables.inc"]["#@#Tools\omnimoapp.exe" Radio Kill][!HideMeterGroup Radio][!ShowMeterGroup RadioOff][!Redraw]
	UpdateDivider=1

[ButtonPlay]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPlay.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*1.052)		
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=1
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPlay ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPlay ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#WRASStream#"][!HideMeter ButtonPlay][!ShowMeter ButtonPause]
	UpdateDivider=1

[ButtonPause]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPause.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*1.052)		
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPause ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPause ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" Off][!HideMeter ButtonPause][!ShowMeter ButtonPlay]
	UpdateDivider=1

[ButtonStations]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnStations.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*1.252)		
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonStations ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonStations ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!ShowMeterGroup Stations]
	UpdateDivider=1


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size
UpdateDivider=-1


;---- Station list ----

[Stationlistbackground]
Meter=Shape
Shape=Rectangle 0,0,(#CRadius#*2),(#CRadius#*2),(#CRadius#*0.1) | Fill Color 0,0,0,200 | StrokeWidth (#CRadius#*0.004) | Stroke Color 255,255,255
Group=Stations
DynamicVariables=1
AntiAlias=1
Hidden=1
MouseLeaveAction=[!HideMeterGroup Stations]
UpdateDivider=-1

[Station1]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.05)	
Text=#StationTitle1#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle1#"][!WriteKeyValue Variables "WRASImage" "#StationImage1#"][!WriteKeyValue Variables "WRASStream" "#StationURL1#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL1#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL1#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption Station1 FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption Station1 FontColor 210,210,210,255]

[Station2]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.28)	
Text=#StationTitle2#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle2#"][!WriteKeyValue Variables "WRASImage" "#StationImage2#"][!WriteKeyValue Variables "WRASStream" "#StationURL2#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL2#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL2#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station3]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.51)	
Text=#StationTitle3#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle3#"][!WriteKeyValue Variables "WRASImage" "#StationImage3#"][!WriteKeyValue Variables "WRASStream" "#StationURL3#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL3#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL3#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station4]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.74)	
Text=#StationTitle4#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle4#"][!WriteKeyValue Variables "WRASImage" "#StationImage4#"][!WriteKeyValue Variables "WRASStream" "#StationURL4#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL4#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL4#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station5]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.97)	
Text=#StationTitle5#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle5#"][!WriteKeyValue Variables "WRASImage" "#StationImage5#"][!WriteKeyValue Variables "WRASStream" "#StationURL5#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL5#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL5#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station6]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*1.20)	
Text=#StationTitle6#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle6#"][!WriteKeyValue Variables "WRASImage" "#StationImage6#"][!WriteKeyValue Variables "WRASStream" "#StationURL6#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL6#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL6#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station7]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*1.43)	
Text=#StationTitle7#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle7#"][!WriteKeyValue Variables "WRASImage" "#StationImage7#"][!WriteKeyValue Variables "WRASStream" "#StationURL7#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL7#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL7#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station8]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*1.66)	
Text=#StationTitle8#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle8#"][!WriteKeyValue Variables "WRASImage" "#StationImage8#"][!WriteKeyValue Variables "WRASStream" "#StationURL8#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL8#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL8#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

