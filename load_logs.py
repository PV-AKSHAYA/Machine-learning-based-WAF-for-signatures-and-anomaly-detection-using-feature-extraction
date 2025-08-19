import pandas as pd

def read_csv_robust(filepath):
    approaches = [
        {'on_bad_lines': 'skip'},
        {'engine': 'python', 'on_bad_lines': 'skip'},
        {'error_bad_lines': False, 'warn_bad_lines': True},
        {'sep': ',', 'engine': 'python', 'on_bad_lines': 'skip'}
    ]
    
    for i, kwargs in enumerate(approaches, 1):
        try:
            if 'on_bad_lines' in kwargs:
                try:
                    df = pd.read_csv(filepath, **kwargs)
                except TypeError:
                    kwargs_old = {k: v for k, v in kwargs.items() if k != 'on_bad_lines'}
                    kwargs_old.update({'error_bad_lines': False, 'warn_bad_lines': True})
                    df = pd.read_csv(filepath, **kwargs_old)
            else:
                df = pd.read_csv(filepath, **kwargs)
            
            print(f"Success! Loaded {len(df)} rows")
            return df
        except Exception as e:
            print(f"Approach {i} failed: {e}")
            continue
    
    raise Exception("All approaches failed")

# Usage
df = read_csv_robust("waf_training_logs.csv")