import math


def summarize(values):
    if not values:
        return {
            "average": 0.0,
            "stddev": 0.0,
            "skewness": 0.0,
            "kurtosis": 0.0,
        }

    count = len(values)
    average = sum(values) / count
    centered = [value - average for value in values]
    second_moment = sum(value ** 2 for value in centered) / count

    if second_moment == 0.0:
        return {
            "average": average,
            "stddev": 0.0,
            "skewness": 0.0,
            "kurtosis": 0.0,
        }

    stddev = math.sqrt(second_moment)
    third_moment = sum(value ** 3 for value in centered) / count
    fourth_moment = sum(value ** 4 for value in centered) / count

    return {
        "average": average,
        "stddev": stddev,
        "skewness": third_moment / stddev ** 3,
        "kurtosis": fourth_moment / second_moment ** 2 - 3.0,
    
