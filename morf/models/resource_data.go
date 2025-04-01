package models

// ResourceData represents the resource data structure from MetaDataModel
type ResourceData struct {
	Locale                  JSONStringArray `gorm:"type:json" json:"locale"`
	NumberOfStringResource  int             `json:"numberOfStringResource"`
	PngDrawables            int             `json:"pngDrawables"`
	NinePatchDrawables      int             `json:"ninePatchDrawables"`
	JpgDrawables            int             `json:"jpgDrawables"`
	GifDrawables            int             `json:"gifDrawables"`
	XMLDrawables            int             `json:"xmlDrawables"`
	DifferentDrawables      int             `json:"differentDrawables"`
	LdpiDrawables           int             `json:"ldpiDrawables"`
	MdpiDrawables           int             `json:"mdpiDrawables"`
	HdpiDrawables           int             `json:"hdpiDrawables"`
	XhdpiDrawables          int             `json:"xhdpiDrawables"`
	XxhdpiDrawables         int             `json:"xxhdpiDrawables"`
	XxxhdpiDrawables        int             `json:"xxxhdpiDrawables"`
	NodpiDrawables          int             `json:"nodpiDrawables"`
	TvdpiDrawables          int             `json:"tvdpiDrawables"`
	UnspecifiedDpiDrawables int             `json:"unspecifiedDpiDrawables"`
	RawResources            int             `json:"rawResources"`
	Menu                    int             `json:"menu"`
	Layouts                 int             `json:"layouts"`
	DifferentLayouts        int             `json:"differentLayouts"`
}
