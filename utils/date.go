package utils

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TimeToDate(t time.Time) bson.DateTime {
	return bson.DateTime(t.UTC().UnixNano() / int64(time.Millisecond))
}

func GetCurrentDateToTime() bson.DateTime {
	return TimeToDate(time.Now().UTC())
}

func GetDifferenceBetweenTwoDates(a, b bson.DateTime) time.Duration {
	ms := int64(a) - int64(b)
	return time.Duration(ms) * time.Millisecond
}

func GetDifferenceAbsTwoDates(a, b bson.DateTime) time.Duration {
	diff := GetDifferenceBetweenTwoDates(a, b)
	if diff < 0 {
		return -diff
	}
	return diff
}

func GetDifferenceAbsTwoDatesInMinutes(a, b bson.DateTime) int {
	return int(GetDifferenceAbsTwoDates(a, b) / time.Minute)
}
