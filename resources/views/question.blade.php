{{-- "Keep me signed in on this machine?" — the package's plain page. Replace it
     with your own design: point `trusted-devices.views.question` at your view
     (it gets $choices and $action), or publish this one
     (--tag=trusted-devices-views). No choice is made for the person. --}}
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ __('Keep me signed in on this machine?') }}</title>
</head>
<body>
    <main>
        <h1>{{ __('Keep me signed in on this machine?') }}</h1>
        <p>{{ __('Until the time ends, this machine does not ask for the code from your authenticator app, and it signs you in by itself. Log out stops the automatic sign-in here.') }}</p>

        <form method="POST" action="{{ $action }}">
            @csrf
            <fieldset>
                <legend>{{ __('Trust this machine') }}</legend>
                @foreach ($choices as $day)
                    <label>
                        <input type="radio" name="days" value="{{ $day }}" required>
                        {{ trans_choice('For :count day|For :count days', $day, ['count' => $day]) }}
                    </label>
                @endforeach
                <label>
                    <input type="radio" name="days" value="never" required>
                    {{ __('No, ask for the code every time') }}
                </label>
            </fieldset>

            @error('days')
                <p role="alert">{{ $message }}</p>
            @enderror

            <p>{{ __('Choose No on a shared or public computer.') }}</p>
            <button type="submit">{{ __('Continue') }}</button>
        </form>
    </main>
</body>
</html>
