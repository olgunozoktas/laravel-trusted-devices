{{-- A host's own question page (the views.question knob). --}}
<form method="POST" action="{{ $action }}">@csrf @foreach ($choices as $day)<input type="radio" name="days" value="{{ $day }}">@endforeach</form>
