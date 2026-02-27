result = (
    lambda x: (
        lambda y: (
            lambda z: x + y + z
        )
    )
)(1)(2)(3)
